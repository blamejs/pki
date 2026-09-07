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
var DS = require("../helpers/der-surgery");
var crypto = require("node:crypto");

// Drop the `critical` BOOLEAN off the Extension whose extnID is `oidName`, re-lengthing every
// enclosing TLV. It forges the non-conformant cert/CRL a hostile responder could send but our own
// builders refuse to emit: a CA certificate's basicConstraints (x509.sign) and a CRL's
// issuingDistributionPoint (crl.sign) are both enforced-critical at build time.
function _dropExtCritical(der, oidName) {
  var oidDer = Buffer.from(pki.asn1.build.oid(pki.oid.byName(oidName)));
  return DS.patch(der, function (node) {
    if (node.constructed && node.tagClass === "universal" && node.tagNumber === pki.asn1.TAGS.SEQUENCE &&
        node.children.length === 3 && node.children[0].tagClass === "universal" &&
        node.children[0].tagNumber === pki.asn1.TAGS.OBJECT_IDENTIFIER &&
        Buffer.from(node.children[0].bytes).equals(oidDer)) {
      return pki.asn1.build.sequence([DS.reencode(node.children[0]), DS.reencode(node.children[2])]);
    }
    return undefined;
  });
}

var CLIENT = signing.makeSigner("ec-p256", { cn: "client" });
var URL = "https://ca.example/cmp";

async function codeOf(p) { try { await p; return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }
function codeOfSync(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || ("RAW:" + (e && e.message)); } }

// Every resumeToken field that names a certificate, so the door rule is asserted on all of them.
var CERT_FIELDS = ["signer", "signerCache", "chain", "caPubs"];
var B = pki.asn1.build;
// A field, and a value that would break the resumed poll if a second read of it reached the state.
var TWO_FACED_FIELDS = [["arm", "kup"], ["polls", 1e9], ["nextPollAt", 8.64e15], ["certReqId", "123"]];

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
  var DISTINCT = await H.manyDistinctCerts(pki, 904);   // a caller pool AT the session cap (ceiling minus the reserve for the CA's own material)

  // ===== 1. happy path: ir -> granted(accepted) -> certConf -> pkiConf -> issued =====
  var s1 = mk([H.ip(0, 0, certDer), H.pkiconf()]);
  var r1 = await s1.session.enroll(H.irRequest(CLIENT.spki));
  check("1a. a granted ir + certConf/pkiConf -> outcome:issued with the leaf certificate", r1.outcome === "issued" && Buffer.isBuffer(r1.certificate) && r1.certificate.equals(certDer));
  check("1b. the transaction confirmed (certConf -> pkiConf completed)", r1.confirmed === true && r1.implicitConfirm === false);
  check("1c. exactly two request legs crossed the seam (ir + certConf)", s1.transport.calls.length === 2);
  check("1d. the transcript records both directions of both legs", r1.transcript.length === 4 && r1.transcript[0].direction === "out" && r1.transcript[1].direction === "in");

  // ===== 1p. a session forwards opts.proxy to the transport on every leg =====
  var sP = mk([H.ip(0, 0, certDer), H.pkiconf()], { proxy: { url: "https://p.example", tls: { useSystemStore: true } } });
  await sP.session.enroll(H.irRequest(CLIENT.spki));
  check("1p. opts.proxy reaches the transport on both legs", sP.transport.calls.length === 2 &&
    !!sP.transport.calls[0].proxy && sP.transport.calls[0].proxy.url === "https://p.example" &&
    !!sP.transport.calls[1].proxy && sP.transport.calls[1].proxy.url === "https://p.example");
  var sNoP = mk([H.ip(0, 0, certDer), H.pkiconf()]);
  await sNoP.session.enroll(H.irRequest(CLIENT.spki));
  check("1p. a session with no proxy forwards none", sNoP.transport.calls[0].proxy === undefined);
  check("1p. a session refuses an unknown option (proxy whitelist did not widen the gate)",
    (await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: mk([]).transport, bogusOpt: 1 }); }))) === "cmp/bad-input");

  // 1p2. A transport the caller supplied but that cannot be called is named at construction. It
  // would otherwise be dropped when the session forwards its options, and the transfer leg would
  // install the real HTTPS client, reaching the CA the caller meant to replace.
  async function badSessionTransport(v) {
    var code = await codeOf(Promise.resolve().then(function () {
      return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: v });
    }));
    return code === "cmp/bad-input" ? "typed" : code;
  }
  check("1p2. a session refuses a non-callable transport", (await badSessionTransport(42)) === "typed");
  check("1p2. a session refuses an explicit null transport", (await badSessionTransport(null)) === "typed");
  check("1p2. a session refuses a present-but-undefined transport", (await badSessionTransport(undefined)) === "typed");
  // A defaults bag carries its options on a prototype. The session keeps own properties only when it
  // copies, so the transport is taken from the caller's object first: reading it off the copy would
  // find none and send every leg to the default client, reaching the CA the caller meant to replace.
  var inheritedCalls = 0;
  var inheritedTransport = function () { inheritedCalls += 1; return Promise.reject(new Error("inherited transport reached")); };
  var bag = Object.create({ transport: inheritedTransport });
  bag.url = URL; bag.key = CLIENT.key; bag.cert = CLIENT.cert; bag.trustAnchors = [H.caCert];
  var inheritedSession = pki.cmp.session(bag);
  var inheritedCode = await codeOf(inheritedSession.enroll(H.irRequest(CLIENT.spki)));
  check("1p3. a session uses a transport inherited from a defaults bag rather than the default client",
    inheritedCalls === 1 && inheritedCode !== "cmp/no-trust-anchors");

  // ===== 1q. the proxy is snapshotted at construction; a mutation during the transaction cannot repoint or re-credential a leg =====
  var pxy = { url: "https://p.example", auth: { username: "u", password: "s3cret" } };
  var sQ = mk([H.ip(0, 0, certDer), H.pkiconf()], { proxy: pxy });
  var pQ = sQ.session.enroll(H.irRequest(CLIENT.spki));
  pxy.url = "https://evil.example";           // mutate while the first leg's build is still awaited
  pxy.auth.password = "leaked";
  await pQ;
  check("1q. a construction-time proxy snapshot isolates every leg from a later caller mutation",
    sQ.transport.calls.length === 2 &&
    sQ.transport.calls[0].proxy.url === "https://p.example" &&
    sQ.transport.calls[1].proxy.url === "https://p.example" &&
    sQ.transport.calls[0].proxy.auth.password === "s3cret" &&
    sQ.transport.calls[1].proxy.auth.password === "s3cret");

  // ===== 1r. an accessor-backed proxy is refused with a typed error, never invoked by the options copy =====
  var invoked = false;
  var accessorOpts = { url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: mk([]).transport };
  Object.defineProperty(accessorOpts, "proxy", { enumerable: true, configurable: true, get: function () { invoked = true; throw new Error("getter-side-effect"); } });
  var accessorCode = await codeOf(Promise.resolve().then(function () { return pki.cmp.session(accessorOpts); }));
  check("1r. an accessor-backed proxy is refused with cmp/bad-input and its getter is never invoked", accessorCode === "cmp/bad-input" && invoked === false);

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
  // sec. 4.4 places enrollment waiting in an ip/cp/kup, never an error message, so a waiting ERROR
  // answering an enrollment is off-profile and refused -- not coerced to a rejected verdict whose own
  // status name reads "waiting". A waiting error carrying failInfo is refused too.
  check("5b. a waiting ERROR answering an enrollment -> refused, not a contradictory rejected verdict", await codeOf(mk([H.errorWaiting()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-error");
  check("5c. a waiting enrollment error carrying failInfo -> refused", await codeOf(mk([H.errorBody(3, ["badRequest"])]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-error");

  // ===== 6. poll-timeout: waiting that never resolves -> terminal poll-timeout verdict =====
  var s6 = mk([H.ip(0, 3), H.pollRep(0, 1), H.pollRep(0, 1), H.pollRep(0, 1)], { maxPolls: 2 });
  var r6 = await s6.session.enroll(H.irRequest(CLIENT.spki));
  check("6a. exceeding maxPolls -> a terminal outcome:poll-timeout VERDICT (not a throw)", r6.outcome === "poll-timeout" && r6.polls === 2);
  check("6b. poll-timeout carries the last waiting PKIStatusInfo diagnostic", r6.status && r6.status.status.code === 3);

  // ===== 6c. resuming a poll in a later process =====
  // A certification authority that answers `waiting` can take longer than the caller is willing to
  // hold a process open. The poll-timeout verdict carries what the next process needs to carry the
  // SAME transaction on: its identifier, the nonce the next request must echo, and which request is
  // being polled (RFC 9810 sec. 5.1.1). Everything else, the protection key and the endpoint, comes
  // from the session the caller builds then.
  check("6c. poll-timeout carries a resumeToken", !!r6.resumeToken && typeof r6.resumeToken === "object");
  var tok = r6.resumeToken;
  check("6d. the token is JSON-serializable, so it survives a process boundary",
    JSON.stringify(tok) === JSON.stringify(JSON.parse(JSON.stringify(tok))));
  check("6e. the token names the transaction, the polled request and the nonce to echo",
    typeof tok.transactionId === "string" && tok.transactionId.length > 0 &&
    typeof tok.certReqId === "string" && typeof tok.recipNonce === "string" && tok.recipNonce.length > 0 &&
    tok.arm === "ip" && tok.polls === 2);
  // The identifier is an integer of any width, so it travels as a decimal string: a token that cannot
  // be serialized is not a resumable one.
  var WIDE_ID = 72057594037927936n;
  var wideTok = (await mk([H.ip(WIDE_ID, 3), H.pollRep(WIDE_ID, 1), H.pollRep(WIDE_ID, 1), H.pollRep(WIDE_ID, 1)], { maxPolls: 2 })
    .session.enroll(H.irRequest(CLIENT.spki, WIDE_ID))).resumeToken;
  check("6e2. a request identifier too wide for a JSON number survives the round trip",
    wideTok.certReqId === "72057594037927936" &&
    JSON.parse(JSON.stringify(wideTok)).certReqId === "72057594037927936");
  // The token also carries the identity the first process authenticated, and the certificates it was
  // sent, so a restart is no weaker and no more dependent on the authority repeating itself.
  check("6e3. the token carries the pinned signer identity", typeof tok.signer === "string" && tok.signer.length > 0);
  // The identity pinned on the first response and the certificate currently used to verify one that
  // omits its extraCerts are carried as two fields, because a same-identity rotation moves the second
  // and never the first. A token naming only the pin verifies under it.
  check("6e4. the token carries the pin and the verification certificate as separate fields",
    Object.prototype.hasOwnProperty.call(tok, "signer") && Object.prototype.hasOwnProperty.call(tok, "signerCache"));
  check("6e5. a token naming only the pin resumes, verifying under it",
    (await mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]).session.resumePoll(
      Object.assign(JSON.parse(JSON.stringify(tok)), { signerCache: null }))).outcome === "issued");

  // A second session resumes it: the grant arrives on the poll, and the certificate is issued.
  var s6r = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  var r6r = await s6r.session.resumePoll(JSON.parse(JSON.stringify(tok)));
  check("6f. a later session resumes the poll and reaches the grant",
    r6r.outcome === "issued" && Buffer.isBuffer(r6r.certificate));
  var firstResumed = pki.schema.cmp.parse(s6r.transport.calls[0].body).header;
  check("6g. the resumed transaction keeps the identifier the token carried",
    Buffer.from(firstResumed.transactionID).toString("hex") === tok.transactionId);
  check("6h. the first resumed request echoes the nonce the token carried",
    Buffer.from(firstResumed.recipNonce).toString("base64") === tok.recipNonce);
  check("6i. the polls the first process spent are carried into the resumed verdict", r6r.polls > 2);

  // The token is state, not authority: a resumed poll verifies protection and binds the issued
  // certificate to the requested key exactly as the first process did.
  var s6bad = mk([H.pollRep(0, 1), H.ip(0, 0, H.signerCert), H.pkiconf()]);
  check("6j. a resumed grant certifying a different key is refused",
    (await codeOf(s6bad.session.resumePoll(JSON.parse(JSON.stringify(tok))))) === "cmp/bad-cert-response");
  var s6untrusted = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], { trustAnchors: [H.intCaCert] });
  check("6k. a resumed response whose protection does not verify is refused",
    typeof (await codeOf(s6untrusted.session.resumePoll(JSON.parse(JSON.stringify(tok))))) === "string");

  // The identity the first process authenticated is carried, so a restart admits no signer the
  // uninterrupted transaction would have refused. Within one process a second trusted signer with its
  // own subject is cmp/untrusted-signer; the resumed poll must answer the same way.
  var s6forge = H.fakeCa(pki, [{ body: H.pollRep(0, 1), foreignSigner: true }, H.ip(0, 0, certDer), H.pkiconf()]);
  var sess6forge = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
    transport: s6forge.transport, sleep: function () { return Promise.resolve(); } });
  check("6y. a resumed response from a DIFFERENT trusted signer is refused, as it is mid-transaction",
    (await codeOf(sess6forge.resumePoll(JSON.parse(JSON.stringify(tok))))) === "cmp/untrusted-signer");

  // The authority's own checkAfter is honored across the restart: resuming before it falls due waits
  // out the remainder rather than polling faster than it asked to be polled.
  var slow = await mk([H.ip(0, 3), H.pollRep(0, 3600), H.pollRep(0, 3600)], { maxPolls: 1 })
    .session.enroll(H.irRequest(CLIENT.spki));
  check("6z. a timeout with an outstanding checkAfter records when the next poll is due",
    slow.outcome === "poll-timeout" && typeof slow.resumeToken.nextPollAt === "number" &&
    slow.resumeToken.nextPollAt > Date.now());
  var waitedMs = 0;
  var s6wait = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
    transport: H.fakeCa(pki, [H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]).transport,
    sleep: function (ms) { waitedMs += ms; return Promise.resolve(); } });
  await s6wait.resumePoll(JSON.parse(JSON.stringify(slow.resumeToken)));
  check("6z2. resuming before the interval falls due waits out the remainder first", waitedMs > 0);
  // The authority's interval is honored, but this process's own wait budget still bounds it: a
  // remainder longer than the budget is a timeout now, carrying the same due time on.
  var tightSlept = 0;
  var s6tight = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
    transport: H.fakeCa(pki, [H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]).transport,
    maxTotalWait: 1, sleep: function (ms) { tightSlept += ms; return Promise.resolve(); } });
  var tight = await s6tight.resumePoll(JSON.parse(JSON.stringify(slow.resumeToken)));
  check("6z3. a remainder longer than this process's wait budget times out now instead of sleeping it out",
    tight.outcome === "poll-timeout" && tightSlept === 0 &&
    tight.resumeToken.nextPollAt === slow.resumeToken.nextPollAt);
  // That session now holds the restored transaction's identifier and nonce, so it is spent even though
  // it sent nothing: enrolling on it would open a new enrollment under another transaction's identity.
  check("6z3b. a session that restored a transaction is consumed even when it sent no request",
    await codeOf(s6tight.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-input");

  // An authority may send the issued certificate's intermediate in a WAITING response and omit it from
  // the grant. The certificates the first process was sent travel in the token, so the resumed grant
  // validates on material the uninterrupted transaction also had.
  check("6z4. the token carries the certificates accumulated before the timeout",
    Array.isArray(tok.caPubs));
  var intLeaf6 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // leaf -> intCaCert -> root
  var capubTok = (await mk([H.ip(0, 3, null, { caPubs: [H.intCaCert] }), H.pollRep(0, 1), H.pollRep(0, 1), H.pollRep(0, 1)], { maxPolls: 2 })
    .session.enroll(H.irRequest(CLIENT.spki))).resumeToken;
  check("6z5. an intermediate delivered on a waiting leg is in the token", capubTok.caPubs.length === 1);
  var resumedIssued = await mk([H.pollRep(0, 1), H.ip(0, 0, intLeaf6), H.pkiconf()])
    .session.resumePoll(JSON.parse(JSON.stringify(capubTok)));
  check("6z6. a resumed grant that omits that intermediate still validates the leaf it signed",
    resumedIssued.outcome === "issued" && resumedIssued.chain.length === 2);
  check("6z7. a token whose caPubs is not an array is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { caPubs: "nope" }))) === "cmp/bad-input");
  var manyPubs = [];
  for (var mp = 0; mp < 65; mp++) manyPubs.push(Buffer.from(H.intCaCert).toString("base64"));
  check("6z8. a token carrying more certificates than a transaction accumulates is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { caPubs: manyPubs }))) === "cmp/bad-input");
  // A token written by an earlier release, or trimmed by a caller, may omit the optional lists and the
  // due time entirely; it still resumes on what it does name.
  var minimalTok = { transactionId: tok.transactionId, recipNonce: tok.recipNonce, certReqId: tok.certReqId,
    arm: tok.arm, requestedSpki: tok.requestedSpki, signer: tok.signer };
  check("6z8b. a token naming only what binds the transaction resumes on that alone",
    (await mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]).session.resumePoll(minimalTok)).outcome === "issued");
  check("6z9. a duplicate in the token's certificates is restored once, not twice",
    (await mk([H.pollRep(0, 1), H.ip(0, 0, intLeaf6), H.pkiconf()]).session.resumePoll(
      Object.assign({}, JSON.parse(JSON.stringify(capubTok)), { caPubs: [capubTok.caPubs[0], capubTok.caPubs[0]] }))).outcome === "issued");

  // A malformed token is refused at the door rather than starting a transaction that cannot be bound.
  check("6l. a token that is not an object is refused",
    await codeOf(mk([]).session.resumePoll("not a token")) === "cmp/bad-input");
  check("6m. a token missing its transaction identifier is refused",
    await codeOf(mk([]).session.resumePoll({ certReqId: 0, recipNonce: tok.recipNonce, arm: "ip" })) === "cmp/bad-input");
  check("6n. a token whose transaction identifier is not hex is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { transactionId: "zz" }))) === "cmp/bad-input");
  // The door refuses before anything is sent, which is what distinguishes a rejected token from a
  // transaction that started and then went wrong.
  var s6arm = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  check("6o. a token naming an arm the session cannot answer is refused before any request is sent",
    (await codeOf(s6arm.session.resumePoll(Object.assign({}, tok, { arm: "rp" })))) === "cmp/bad-input" &&
    s6arm.transport.calls.length === 0);
  var s6nonce = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  check("6o2. a token whose recipNonce is not canonical base64 is refused before any request is sent",
    (await codeOf(s6nonce.session.resumePoll(Object.assign({}, tok, { recipNonce: "not base64!!" })))) === "cmp/bad-input" &&
    s6nonce.transport.calls.length === 0);
  var s6extra = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  check("6o3. a token carrying an unknown field is refused rather than read past",
    (await codeOf(s6extra.session.resumePoll(Object.assign({}, tok, { endpoint: "https://elsewhere.example" })))) === "cmp/bad-input" &&
    s6extra.transport.calls.length === 0);
  check("6p. a session that already ran a transaction refuses to resume one",
    await codeOf(s6.session.resumePoll(JSON.parse(JSON.stringify(tok)))) === "cmp/bad-input");
  check("6q. a token whose transaction identifier is empty is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { transactionId: "" }))) === "cmp/bad-input");
  check("6r. a token whose recipNonce is empty is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { recipNonce: "" }))) === "cmp/bad-input");
  check("6s. a token whose certReqId is not an integer is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { certReqId: 1.5 }))) === "cmp/bad-input");
  check("6t. a token whose polls count is negative is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { polls: -1 }))) === "cmp/bad-input");
  check("6t2. a token whose certReqId is not a decimal string is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { certReqId: "seven" }))) === "cmp/bad-input");
  // The reader accepts every identifier an enrollment can put in a token, and refuses a decimal string
  // too long to convert without the conversion itself becoming the cost.
  var sNeg = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  check("6t3. a token whose certReqId is a negative identifier an enrollment can carry is read",
    (await codeOf(sNeg.session.resumePoll(Object.assign({}, tok, { certReqId: "-2" })))) !== "cmp/bad-input" &&
    sNeg.transport.calls.length > 0);
  check("6t3b. a token whose certReqId is longer than the widest identifier a request can carry is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { certReqId: "9".repeat(49153) }))) === "cmp/bad-input");
  // A wait split across processes reads the same as one held in a single process: a resumed poll that
  // read no certificate response of its own still reports the waiting status, because that is the status
  // a transaction a token can continue is in.
  var sTimeoutA = mk([H.ip(0, 3), H.pollRep(0, 1)], { maxPolls: 1 });
  var timeoutStraight = await sTimeoutA.session.enroll(H.irRequest(CLIENT.spki));
  var sTimeoutB = mk([H.pollRep(0, 1)], { maxPolls: 1 });
  var timeoutResumed = await sTimeoutB.session.resumePoll(JSON.parse(JSON.stringify(timeoutStraight.resumeToken)));
  check("6t3d. a resumed timeout that read no certificate response still reports the waiting status",
    timeoutStraight.outcome === "poll-timeout" && timeoutStraight.status.status.code === 3 &&
    timeoutResumed.outcome === "poll-timeout" && timeoutResumed.status.status.code === 3 &&
    timeoutResumed.status.status.name === timeoutStraight.status.status.name &&
    timeoutResumed.resumeToken != null);
  // The authority's own diagnostics are not reproduced from stored state, so a verdict never presents
  // text as the authority's that the authority did not send in this exchange.
  check("6t3d2. and it reports no diagnostic string of its own",
    timeoutResumed.status.statusString === null && timeoutResumed.status.failInfo === null);
  // The due-time handoff, which sends no request at all, reports the same status.
  var farTok = JSON.parse(JSON.stringify(timeoutStraight.resumeToken));
  farTok.nextPollAt = Date.now() + 3600000;
  var sFar = mk([H.pollRep(0, 1)], { maxTotalWait: 1 });
  var farOut = await sFar.session.resumePoll(farTok);
  check("6t3d3. a resume whose remaining wait exceeds the budget reports it too, sending no request",
    farOut.outcome === "poll-timeout" && farOut.status.status.code === 3 && sFar.transport.calls.length === 0);

  // A nonce shorter than a received message is allowed to carry could not have come from a response, so
  // it is refused before it is echoed into a request that cannot continue the chain.
  var SHORT_NONCES = ["AA==", Buffer.alloc(15, 7).toString("base64"), ""];
  for (var sn = 0; sn < SHORT_NONCES.length; sn++) {
    var sShort = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
    check("6t3e. a token whose recipNonce is shorter than a response nonce is refused before any request (" + sn + ")",
      (await codeOf(sShort.session.resumePoll(Object.assign({}, tok, { recipNonce: SHORT_NONCES[sn] })))) === "cmp/bad-input" &&
      sShort.transport.calls.length === 0);
  }
  // The same question of the identifier: a first message opens a transaction with 128 bits, so a token
  // naming any other width names a transaction it cannot have opened.
  var ODD_TXNS = [Buffer.alloc(8, 3).toString("hex"), Buffer.alloc(17, 3).toString("hex"), ""];
  for (var ot = 0; ot < ODD_TXNS.length; ot++) {
    var sTxn = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
    check("6t3g. a token whose transactionId is not the width a first message opens with is refused (" + ot + ")",
      (await codeOf(sTxn.session.resumePoll(Object.assign({}, tok, { transactionId: ODD_TXNS[ot] })))) === "cmp/bad-input" &&
      sTxn.transport.calls.length === 0);
  }
  var sAtFloor = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  check("6t3f. a token whose recipNonce is exactly at that floor is read",
    (await codeOf(sAtFloor.session.resumePoll(Object.assign({}, tok, { recipNonce: Buffer.alloc(16, 7).toString("base64") })))) !== "cmp/bad-input" &&
    sAtFloor.transport.calls.length > 0);

  // The door accepts exactly the widths the next request can encode, so an identifier the encoder
  // refuses cannot pass the door and consume the session before the encoding is attempted.
  var sWide = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  var wideCode = await codeOf(sWide.session.resumePoll(Object.assign({}, tok, { certReqId: "9".repeat(45000) })));
  var wideSent = sWide.transport.calls.length;
  await codeOf(sWide.session.resumePoll(JSON.parse(JSON.stringify(tok))));
  check("6t3b1. a token whose certReqId is wider than a request identifier encodes is refused, and the session it was handed to still resumes",
    wideCode === "cmp/bad-input" && wideSent === 0 && sWide.transport.calls.length > 0);
  // Every spelling a numeric conversion would read but a session never writes. Each names a different
  // request than it appears to, so each is refused before the saved nonce is spent.
  var NOT_DECIMAL = ["0x10", "0b10", "0o10", "+10", " 10", "10 ", "\t10", "007", "-0", "-", "1_0", "1e3", "", "10.0"];
  for (var nd = 0; nd < NOT_DECIMAL.length; nd++) {
    var sDec = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
    check("6t3b2. a token whose certReqId is " + JSON.stringify(NOT_DECIMAL[nd]) + " is refused before any request",
      (await codeOf(sDec.session.resumePoll(Object.assign({}, tok, { certReqId: NOT_DECIMAL[nd] })))) === "cmp/bad-input" &&
      sDec.transport.calls.length === 0);
  }
  // The spellings a session does write are still read.
  var DECIMAL = ["0", "-1", "10", "9007199254740993"];
  for (var dd = 0; dd < DECIMAL.length; dd++) {
    var sOk = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
    check("6t3b3. a token whose certReqId is " + JSON.stringify(DECIMAL[dd]) + " is read",
      (await codeOf(sOk.session.resumePoll(Object.assign({}, tok, { certReqId: DECIMAL[dd] })))) !== "cmp/bad-input" &&
      sOk.transport.calls.length > 0);
  }
  // The response cap is a bound the token decode measures against, so it is refused where it is given.
  check("6t3b4. a session built with a fractional response cap is refused at construction",
    await codeOf(Promise.resolve().then(function () {
      return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
        transport: H.fakeCa(pki, []).transport, maxResponseBytes: 1.5 });
    })) === "cmp/bad-input");
  check("6t4. a token whose chain is not an array is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { chain: tok.signer }))) === "cmp/bad-input");
  check("6t5. a token whose next-poll instant is not a number is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { nextPollAt: "soon" }))) === "cmp/bad-input");
  // A token is any object a caller hands in. Each field is taken once, so a field that answers one way
  // to the check and another to the restore cannot put the second answer into the resumed state.
  for (var tf = 0; tf < TWO_FACED_FIELDS.length; tf++) {
    var twoFaced = {};
    var names = Object.keys(tok);
    for (var tn = 0; tn < names.length; tn++) twoFaced[names[tn]] = tok[names[tn]];
    (function (name, second) {
      var reads = 0, first = tok[name];
      Object.defineProperty(twoFaced, name, { enumerable: true, get: function () { return reads++ === 0 ? first : second; } });
    }(TWO_FACED_FIELDS[tf][0], TWO_FACED_FIELDS[tf][1]));
    var sTwo = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
    var twoCode = await codeOf(sTwo.session.resumePoll(twoFaced));
    check("6t5. a token whose " + TWO_FACED_FIELDS[tf][0] + " answers differently on a second read carries the checked value",
      twoCode === "NO-THROW" && sTwo.transport.calls.length > 0);
  }
  // Every field of a token that names a certificate is parsed at the door, so stored bytes that are not
  // one cannot spend the nonce the token carries before they are found to be unusable.
  var notCertB64 = Buffer.from("nope").toString("base64");
  for (var cf = 0; cf < CERT_FIELDS.length; cf++) {
    var field = CERT_FIELDS[cf];
    var bad = Object.assign({}, tok);
    bad[field] = field === "chain" || field === "caPubs" ? [notCertB64] : notCertB64;
    var sBad = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
    check("6t6. a token whose " + field + " is not a certificate is refused before any request",
      (await codeOf(sBad.session.resumePoll(bad))) === "cmp/bad-input" && sBad.transport.calls.length === 0);
  }
  // Stored state that is not a public key is read at the door, so it cannot advance the exchange with
  // the authority and only then be found unusable.
  // The key a token names came from the caller's own request, not from a response, so a response cap
  // below its size does not refuse the token that carries it.
  var rsaSpki = signing.makeSigner("rsa").spki;
  var sBigKey = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], { maxResponseBytes: rsaSpki.length - 1 });
  check("6t3c. a response cap below the requested key does not refuse the token that names it",
    (await codeOf(sBigKey.session.resumePoll(Object.assign({}, tok, { requestedSpki: rsaSpki.toString("base64") })))) !== "cmp/bad-input" &&
    sBigKey.transport.calls.length > 0);

  // The chain that validates the signer can hold a certificate the caller passed in opts.intermediates.
  // It never crossed the wire, so it is bounded by the codec rather than by the response size, and a
  // session whose response cap is smaller than that certificate still restores the token it names.
  var bareF = H.fakeCa(pki, [H.ip(0, 3), H.pollRep(0, 1)], { deepSigner: true, deepSignerBareExtra: true });
  var bareSess = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
    intermediates: [H.intCaCert], transport: bareF.transport, sleep: function () { return Promise.resolve(); }, maxPolls: 1 });
  var bareTok = (await bareSess.enroll(H.irRequest(CLIENT.spki))).resumeToken;
  check("6t7. a token from a caller-supplied chain names that certificate",
    bareTok != null && bareTok.chain.length === 2 && Buffer.from(bareTok.chain[0], "base64").length === H.intCaCert.length);
  var tightF = H.fakeCa(pki, [H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], { deepSigner: true, deepSignerBareExtra: true });
  var tightSess = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
    intermediates: [H.intCaCert], maxResponseBytes: H.intCaCert.length - 1, transport: tightF.transport,
    sleep: function () { return Promise.resolve(); } });
  check("6t7b. a response cap below that certificate does not refuse the token that names it",
    (await codeOf(tightSess.resumePoll(JSON.parse(JSON.stringify(bareTok))))) !== "cmp/bad-input" &&
    tightF.transport.calls.length > 0);
  // A resumed transaction is held to what the first process actually had. Driving the SAME response
  // sequence both ways, a token that names no cached verification certificate must not let the pinned
  // identity stand in for one: the grant is validated from the certificates the authority sent, and a
  // sequence that leaves none of them behind is refused in one process and in two alike.
  // Implicit confirmation is negotiated in the request the token continues, so the token carries it and
  // the resumed poll confirms the way that request asked, whatever the resuming session's options say.
  var icA = mk([H.ip(0, 3), H.pollRep(0, 1)], { implicitConfirm: true, maxPolls: 1 });
  var icTok = (await icA.session.enroll(H.irRequest(CLIENT.spki))).resumeToken;
  check("6t13. a token records that its request asked for implicit confirmation", icTok != null && icTok.implicitConfirm === true);
  var icB = mk([{ body: H.ip(0, 0, certDer), generalInfo: H.IMPLICIT_CONFIRM_GI }]);
  var icOut = await icB.session.resumePoll(JSON.parse(JSON.stringify(icTok)));
  check("6t13b. a session that never set the option still confirms that grant implicitly, sending no certConf",
    icOut.outcome === "issued" && icOut.implicitConfirm === true && icB.transport.calls.length === 1);
  // The other direction is the one that must not open: a session setting the option cannot make a
  // transaction whose request never asked for it accept an implicit-confirm indication.
  var plainA = mk([H.ip(0, 3), H.pollRep(0, 1)], { maxPolls: 1 });
  var plainTok = (await plainA.session.enroll(H.irRequest(CLIENT.spki))).resumeToken;
  var plainB = mk([{ body: H.ip(0, 0, certDer), generalInfo: H.IMPLICIT_CONFIRM_GI }, H.pkiconf()], { implicitConfirm: true });
  var plainOut = await plainB.session.resumePoll(JSON.parse(JSON.stringify(plainTok)));
  check("6t13c. a token whose request did not ask for implicit confirmation still sends its certConf",
    plainTok.implicitConfirm === false && plainOut.outcome === "issued" &&
    plainOut.implicitConfirm === false && plainB.transport.calls.length === 2);
  check("6t13d. a token that says how its transaction confirms in anything but a boolean is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, plainTok, { implicitConfirm: "yes" }))) === "cmp/bad-input");
  var sOmit = mk([H.pollRep(0, 1), { body: H.ip(0, 0, certDer), generalInfo: H.IMPLICIT_CONFIRM_GI }, H.pkiconf()],
    { implicitConfirm: true });
  var omitTok = JSON.parse(JSON.stringify(icTok));
  delete omitTok.implicitConfirm;
  var omitOut = await sOmit.session.resumePoll(omitTok);
  check("6t13f. a token omitting it resumes as though the request asked for nothing, so the grant is confirmed explicitly",
    omitOut.outcome === "issued" && omitOut.implicitConfirm === false);
  var sVet = mk([{ body: H.ip(0, 0, certDer), generalInfo: H.IMPLICIT_CONFIRM_GI }], { acceptCert: function () { return true; } });
  check("6t13e. an implicit-confirm token handed to a session that vets grants is refused before any request",
    (await codeOf(sVet.session.resumePoll(JSON.parse(JSON.stringify(icTok))))) === "cmp/bad-input" &&
    sVet.transport.calls.length === 0);

  var waitLeg = { body: H.ip(0, 3), noExtraCerts: true };
  var pollLeg = { body: H.pollRep(0, 1), noExtraCerts: true };
  var grantLeg = { body: H.ip(0, 0, certDer), noExtraCerts: true };
  var confLeg = { body: H.pkiconf(), noExtraCerts: true };
  var straight = mk([waitLeg, pollLeg, grantLeg, confLeg], { expectedSender: H.signerCert });
  var straightCode = await codeOf(straight.session.enroll(H.irRequest(CLIENT.spki)));
  var splitA = mk([waitLeg, pollLeg], { expectedSender: H.signerCert, maxPolls: 1 });
  var splitTok = (await splitA.session.enroll(H.irRequest(CLIENT.spki))).resumeToken;
  var splitB = mk([grantLeg, confLeg], { expectedSender: H.signerCert });
  var splitCode = splitTok == null ? "NO-TOKEN" : await codeOf(splitB.session.resumePoll(JSON.parse(JSON.stringify(splitTok))));
  check("6t8. the same response sequence reaches the same verdict whether it runs in one process or two",
    splitTok != null && splitTok.signerCache == null && splitCode === straightCode);
  // The equivalence holds in both directions, including where the transaction fails. A session that
  // authenticated bare responses through opts.expectedSender is configuration, not transaction state, so
  // a resumed session without it refuses exactly where an uninterrupted one without it refuses, and the
  // pinned identity does not quietly stand in for the certificate the option supplied.
  var bareSeq = [waitLeg, pollLeg, grantLeg, confLeg];
  var noOptStraight = await codeOf(mk(bareSeq).session.enroll(H.irRequest(CLIENT.spki)));
  var noOptA = mk([waitLeg, pollLeg], { expectedSender: H.signerCert, maxPolls: 1 });
  var noOptTok = (await noOptA.session.enroll(H.irRequest(CLIENT.spki))).resumeToken;
  var noOptResumed = await codeOf(mk([grantLeg, confLeg]).session.resumePoll(JSON.parse(JSON.stringify(noOptTok))));
  check("6t8b. a session that does not carry the sender pin refuses a bare response the same way in one process or two",
    noOptStraight === "cmp/signer-cert-not-found" && noOptResumed === noOptStraight);

  // The chain is bounded by the path length rather than by the response size, so a token naming more
  // certificates than a path can hold is refused while a caller's own oversized intermediate is not.
  var longChain = [];
  for (var oc = 0; oc < 101; oc++) longChain.push(H.intCaCert.toString("base64"));
  var sLongChain = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], { intermediates: [H.intCaCert] });
  check("6t7c. a token naming more chain certificates than a path holds is refused before any request",
    (await codeOf(sLongChain.session.resumePoll(Object.assign({}, tok, { chain: longChain })))) === "cmp/bad-input" &&
    sLongChain.transport.calls.length === 0);
  var sFitChain = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], { intermediates: [H.intCaCert] });
  check("6t7d. a chain at that length is read",
    (await codeOf(sFitChain.session.resumePoll(Object.assign({}, tok, { chain: longChain.slice(0, 100) })))) !== "cmp/bad-input" &&
    sFitChain.transport.calls.length > 0);

  // Well-formed DER in the shape of a public key is not one: the door reads the SEQUENCE widths and the
  // BIT STRING, so DER that merely decodes cannot be fingerprinted as a key and spend the saved nonce.
  var notSpki = [
    ["undecodable bytes", Buffer.from("nope")],
    ["a SEQUENCE whose second element is an INTEGER", B.sequence([B.sequence([B.oid("1.2.3")]), B.integer(1n)])],
    ["a SEQUENCE of one element", B.sequence([B.sequence([B.oid("1.2.3")])])],
    ["an AlgorithmIdentifier of three elements", B.sequence([B.sequence([B.oid("1.2.3"), B.nullValue(), B.nullValue()]), B.bitString(Buffer.from([1, 2, 3]), 0)])],
    ["a subjectPublicKey that is not octet-aligned", B.sequence([B.sequence([B.oid("1.2.3")]), B.bitString(Buffer.from([1, 2, 4]), 2)])],
  ];
  for (var ns = 0; ns < notSpki.length; ns++) {
    var s6badKey = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
    check("6t6b. a token whose requested key is " + notSpki[ns][0] + " is refused before any request",
      (await codeOf(s6badKey.session.resumePoll(Object.assign({}, tok, { requestedSpki: notSpki[ns][1].toString("base64") })))) === "cmp/bad-input" &&
      s6badKey.transport.calls.length === 0);
  }
  // The certificate pool a token restores is held to the same aggregate size a live transaction
  // accumulates under, so stored state cannot ask for a larger allocation than the exchange could.
  // Every entry is a real certificate under the per-response cap, so only their SUM can refuse this:
  // the pool a live transaction is allowed to accumulate is twice that cap.
  var poolCap = { maxResponseBytes: H.caCert.length * 4 };
  var overPool = [];
  for (var bp = 0; bp < 12; bp++) overPool.push(H.caCert.toString("base64"));
  var s6pool = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], poolCap);
  check("6t6c. a token whose certificate pool exceeds the transaction's byte budget is refused before any request",
    (await codeOf(s6pool.session.resumePoll(Object.assign({}, tok, { caPubs: overPool })))) === "cmp/bad-input" &&
    s6pool.transport.calls.length === 0);
  check("6t6d. the same pool one entry short of the budget is accepted",
    (await codeOf(mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], poolCap)
      .session.resumePoll(Object.assign({}, tok, { caPubs: overPool.slice(0, 7) })))) === "NO-THROW");
  // The whole-message sentinel is what a PKCS#10 enrollment polls under, so it must resume.
  var p10req = await pki.csr.sign({ subject: [{ commonName: "leaf" }], subjectPublicKey: CLIENT.spki }, CLIENT.key);
  var p10tok = (await mk([H.cp(-1, 3), H.pollRep(-1, 1), H.pollRep(-1, 1), H.pollRep(-1, 1)], { maxPolls: 2 })
    .session.enroll({ p10cr: p10req })).resumeToken;
  check("6t7. a PKCS#10 enrollment's token names the whole-message sentinel", p10tok.certReqId === "-1");
  // Whatever an enrollment arm puts in a token, its own reader accepts: an arm that emitted a field the
  // reader refuses would produce a timeout no operator could resume. Driven per arm, token straight back.
  var ROUND_TRIP = [
    ["ir", function () { return H.irRequest(CLIENT.spki); }, H.ip, 0],
    ["p10cr", function () { return { p10cr: p10req }; }, H.cp, -1],
  ];
  for (var rt = 0; rt < ROUND_TRIP.length; rt++) {
    var rtArm = ROUND_TRIP[rt][0], rtReq = ROUND_TRIP[rt][1], rtResp = ROUND_TRIP[rt][2], rtId = ROUND_TRIP[rt][3];
    var rtTok = (await mk([rtResp(rtId, 3), H.pollRep(rtId, 1)], { maxPolls: 1 }).session.enroll(rtReq())).resumeToken;
    var rtOut = await mk([H.pollRep(rtId, 1), rtResp(rtId, 0, certDer), H.pkiconf()])
      .session.resumePoll(JSON.parse(JSON.stringify(rtTok)));
    check("6t7b. a " + rtArm + " enrollment's own token resumes to the outcome the arm reaches",
      rtTok != null && rtOut.outcome === "issued" && rtOut.confirmed === true);
  }
  // A shared-secret session pins no signer certificate, since there is none, so its token carries none
  // and the resumed poll authenticates the same way the first process did: by the secret.
  var MAC_SECRET = "shared-secret-resume";
  var s6macF = H.fakeCa(pki, [H.ip(0, 3), H.pollRep(0, 1), H.pollRep(0, 1), H.pollRep(0, 1)], { macSecret: MAC_SECRET });
  var s6mac = pki.cmp.session({ url: URL, mac: { secret: MAC_SECRET }, transport: s6macF.transport,
    sleep: function () { return Promise.resolve(); }, maxPolls: 2 });
  var macTok = (await s6mac.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key))).resumeToken;
  check("6t9. a shared-secret session's token carries no signer certificate", macTok.signer === null && macTok.chain.length === 0);
  var s6macR = pki.cmp.session({ url: URL, mac: { secret: MAC_SECRET },
    transport: H.fakeCa(pki, [H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], { macSecret: MAC_SECRET }).transport,
    sleep: function () { return Promise.resolve(); } });
  check("6t10. and it resumes under the same secret",
    (await s6macR.resumePoll(JSON.parse(JSON.stringify(macTok)))).outcome === "issued");
  // How a transaction authenticates is fixed when it opens. The two flavors bind a response by different
  // things, the pinned signer identity and the shared secret, so neither resumes the other's transaction.
  check("6t10b. a shared-secret token names its protection", macTok.protection === "mac");
  var sigTokP = JSON.parse(JSON.stringify(tok));
  check("6t10c. a signature token names its protection", sigTokP.protection === "signature");
  var sSigForMac = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  check("6t10d. a shared-secret transaction is not resumed by a signature session",
    (await codeOf(sSigForMac.session.resumePoll(JSON.parse(JSON.stringify(macTok))))) === "cmp/bad-input" &&
    sSigForMac.transport.calls.length === 0);
  var macForSigF = H.fakeCa(pki, [H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], { macSecret: MAC_SECRET });
  var macForSig = pki.cmp.session({ url: URL, mac: { secret: MAC_SECRET }, transport: macForSigF.transport,
    sleep: function () { return Promise.resolve(); } });
  check("6t10e. a signature transaction is not resumed by a shared-secret session",
    (await codeOf(macForSig.resumePoll(sigTokP))) === "cmp/bad-input" && macForSigF.transport.calls.length === 0);
  check("6t10f. a token naming a protection that is neither is refused",
    await codeOf(mk([]).session.resumePoll(Object.assign({}, tok, { protection: "none" }))) === "cmp/bad-input");
  // A token trimmed of the field is read from its own contents, never from the session reading it, or a
  // session of either flavor could answer for a transaction of the other.
  var trimmedSig = JSON.parse(JSON.stringify(tok));
  delete trimmedSig.protection;
  var macForTrimmedF = H.fakeCa(pki, [H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], { macSecret: MAC_SECRET });
  var macForTrimmed = pki.cmp.session({ url: URL, mac: { secret: MAC_SECRET }, transport: macForTrimmedF.transport,
    sleep: function () { return Promise.resolve(); } });
  check("6t10g. a trimmed signature token is not resumed by a shared-secret session",
    (await codeOf(macForTrimmed.resumePoll(trimmedSig))) === "cmp/bad-input" && macForTrimmedF.transport.calls.length === 0);
  var trimmedMac = JSON.parse(JSON.stringify(macTok));
  delete trimmedMac.protection;
  var sigForTrimmed = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  check("6t10h. a trimmed shared-secret token is not resumed by a signature session",
    (await codeOf(sigForTrimmed.session.resumePoll(trimmedMac))) === "cmp/bad-input" &&
    sigForTrimmed.transport.calls.length === 0);
  var macForTrimmed2F = H.fakeCa(pki, [H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()], { macSecret: MAC_SECRET });
  var macForTrimmed2 = pki.cmp.session({ url: URL, mac: { secret: MAC_SECRET }, transport: macForTrimmed2F.transport,
    sleep: function () { return Promise.resolve(); } });
  check("6t10i. and a trimmed token still resumes under the flavor it was made with",
    (await macForTrimmed2.resumePoll(JSON.parse(JSON.stringify(trimmedMac)))).outcome === "issued");

  check("6t8. and that token resumes to the grant",
    (await mk([H.pollRep(-1, 1), H.cp(-1, 0, certDer), H.pkiconf()]).session.resumePoll(
      JSON.parse(JSON.stringify(p10tok)))).outcome === "issued");
  check("6u. a token omitting the polls count resumes from zero, counting only this process's polls",
    (await mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]).session.resumePoll(
      Object.assign({}, tok, { polls: undefined }))).polls === 2);
  // A token is state a caller stored, and storage is where it can be edited, so dropping a field must
  // not drop the check it feeds: the key the grant is bound to and the identity every response is held
  // to are both required rather than optional.
  var s6noKey = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  check("6v. a token with the requested key removed is refused before any request, not resumed without the key binding",
    (await codeOf(s6noKey.session.resumePoll(Object.assign({}, tok, { requestedSpki: null })))) === "cmp/bad-input" &&
    s6noKey.transport.calls.length === 0);
  var s6noPin = mk([H.pollRep(0, 1), H.ip(0, 0, certDer), H.pkiconf()]);
  check("6v2. a signature session refuses a token with the signer identity removed, before any request",
    (await codeOf(s6noPin.session.resumePoll(Object.assign({}, tok, { signer: null })))) === "cmp/bad-input" &&
    s6noPin.transport.calls.length === 0);

  // A resumed poll reaches the same terminal verdicts the first process could: a rejection the
  // authority finally issues, and a further timeout that hands back a token again.
  check("6w. a rejection on a resumed poll is a terminal verdict",
    (await mk([H.pollRep(0, 1), H.ipRejected(0)]).session.resumePoll(JSON.parse(JSON.stringify(tok)))).outcome === "rejected");
  var again = await mk([H.pollRep(0, 1), H.pollRep(0, 1), H.pollRep(0, 1)], { maxPolls: 2 })
    .session.resumePoll(JSON.parse(JSON.stringify(tok)));
  check("6x. a resumed poll that times out again hands back a token, so a wait spans any number of processes",
    again.outcome === "poll-timeout" && !!again.resumeToken &&
    again.resumeToken.transactionId === tok.transactionId && again.polls === tok.polls + 2);

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
  // The session entry points require a PLAIN record, not merely a typeof-object: an array or an exotic
  // (Date/Map) that carries the right property names would otherwise pass the object gate and read as a
  // keyless record -- session() building a working session from an array whose option props were
  // hand-assigned, a request verb driving a transaction from one. guard.identifier.assertPlainRecord
  // refuses that shape at each door.
  var arrOpts = []; arrOpts.url = URL; arrOpts.key = CLIENT.key; arrOpts.cert = CLIENT.cert; arrOpts.trustAnchors = [H.caCert];
  check("18d. session(<array carrying option props>) -> cmp/bad-input (an array is not a plain options record)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session(arrOpts); })) === "cmp/bad-input");
  check("18e. session(<Date>) -> cmp/bad-input (an exotic is not a plain options record)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session(new Date()); })) === "cmp/bad-input");
  check("18f. an array enroll request (arm prop assigned) -> cmp/bad-input", await codeOf((function () { var a = []; a.ir = {}; return mk([H.pkiconf()]).session.enroll(a); })()) === "cmp/bad-input");
  check("18g. an array revoke request (certificate prop assigned) -> cmp/bad-input", await codeOf((function () { var a = []; a.certificate = CLIENT.cert; return mk([H.pkiconf()]).session.revoke(a); })()) === "cmp/bad-input");
  check("18h. an array info request (caCerts prop assigned) -> cmp/bad-input", await codeOf((function () { var a = []; a.caCerts = true; return mk([H.pkiconf()]).session.info(a); })()) === "cmp/bad-input");

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
  var r24 = await s24.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key));
  check("24. a PBMAC1-protected transaction issues end to end (build + verify under the shared secret)", r24.outcome === "issued" && r24.confirmed === true && Buffer.isBuffer(r24.certificate));

  // ===== 25. a hashless-signature issued cert (Ed25519) -> the certConf certHash defaults to SHA-256 =====
  var ed25 = await H.makeEd25519Cert(pki, CLIENT.spki);
  var s25 = mk([H.ip(0, 0, ed25.cert), H.pkiconf()], { trustAnchors: [H.caCert, ed25.ca] });   // the Ed25519 CA is a trust anchor so the leaf validates
  var r25 = await s25.session.enroll(H.irRequest(CLIENT.spki));
  var conf25 = pki.schema.cmp.parse(s25.transport.calls[1].body);   // the certConf request
  var sentHash = conf25.body.decoded[0].certHash;
  var wantHash = require("node:crypto").createHash("sha256").update(ed25.cert).digest();
  check("25. an Ed25519-signed issued cert -> the certConf certHash is computed under SHA-256 (the hashless default)",
    r25.outcome === "issued" && r25.certificate.equals(ed25.cert) && Buffer.from(sentHash).equals(wantHash));

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
  var ed28 = await H.makeEd25519Cert(pki, CLIENT.spki);   // Ed25519: the OID does NOT convey a hash
  var s28b = mk([H.ip(0, 0, ed28.cert), H.pkiconf()], { trustAnchors: [H.caCert, ed28.ca] });
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
  // The arm is a CertificationRequest in whichever byte shape the caller holds, and the session copies
  // records field by field, so every accepted shape has to survive that as bytes rather than as an
  // object of indices.
  for (var p10Shape of [["Uint8Array", new Uint8Array(p10)], ["DataView", new DataView(new Uint8Array(p10).buffer)],
    ["ArrayBuffer", new Uint8Array(p10).buffer]]) {
    check("31a. a p10cr arm given as a " + p10Shape[0] + " enrolls the same way",
      (await mk([H.cp(-1, 0, certDer), H.pkiconf()]).session.enroll({ p10cr: p10Shape[1] })).outcome === "issued");
  }

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

  // ===== 36. a response that omits its senderNonce -> cmp/bad-sender-nonce (RFC 9483 sec. 3.5, caught at verify) =====
  check("36. a waiting response omitting senderNonce is refused at verify -> cmp/bad-sender-nonce (RFC 9483 sec. 3.5)",
    await codeOf(mk([{ body: H.ip(0, 3), noSenderNonce: true }, H.pollRep(0, 1)]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-sender-nonce");

  // ===== 36b. RFC 9483 sec. 4.4: a waiting ip/cp/kup CertResponse must not carry failInfo (a wait is not a failure) =====
  // Without the check the failInfo is ignored and the same leg sequence would poll to issuance (the sec. 3 happy
  // path); the check refuses the contradictory response on the first leg. A granted status carrying failInfo is
  // already refused upstream (the parser's failInfo/certifiedKeyPair mutual exclusion, then the no-certificate check).
  check("36b. a waiting ip carrying failInfo is refused -> cmp/unexpected-arm (RFC 9483 sec. 4.4)",
    await codeOf(mk([H.ip(0, 3, null, { failInfo: ["badRequest"] }), H.pollRep(0, 5), H.pollRep(0, 5), H.ip(0, 0, certDer), H.pkiconf()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/unexpected-arm");

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
  var pss45 = await H.makePssCert(pki, CLIENT.spki);
  var s45 = mk([H.ip(0, 0, pss45.cert), H.pkiconf()], { trustAnchors: [H.caCert, pss45.ca] });
  var r45 = await s45.session.enroll(H.irRequest(CLIENT.spki));
  var cc45 = pki.schema.cmp.parse(s45.transport.calls[1].body).body.decoded[0];
  var wantH45 = require("node:crypto").createHash("sha384").update(pss45.cert).digest();
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

  // ===== 49. a clustered CA rotates its protection cert mid-transaction: a later leg's OWN signer wins over the cache =====
  var s49f = H.fakeCa(pki, [H.ip(0, 0, certDer), { body: H.pkiconf(), rotateSigner: true }]);   // certConf answered by a DIFFERENT (valid) signer
  var s49 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s49f.transport, sleep: function () { return Promise.resolve(); } });
  var r49 = await s49.enroll(H.irRequest(CLIENT.spki));
  check("49. a later leg signed by a rotated (but valid, anchored) signer verifies via its OWN cert, not the cached one -> issued", r49.outcome === "issued" && r49.confirmed === true);

  // ===== 50. the granting response's authenticated caPubs are surfaced in the returned chain (not dropped) =====
  var s50 = mk([H.ip(0, 0, certDer, { caPubs: [H.caCert] }), H.pkiconf()]);
  var r50 = await s50.session.enroll(H.irRequest(CLIENT.spki));
  check("50. caPubs delivered in the grant are retained in chain (leaf + issuer certs), as chain material not anchors",
    r50.outcome === "issued" && r50.chain.length === 2 && r50.chain[0].equals(certDer) && r50.chain[1].equals(H.caCert));

  // ===== 51. a central-key-generation privateKey in the grant is delivered only when the caller
  //           says it accepts one (RFC 9483 sec. 4.1.6) =====
  var privBlob = pki.asn1.build.sequence([pki.asn1.build.integer(0n)]);   // any DER stands in for the encrypted key payload
  check("51. a granted CertResponse carrying a server-generated privateKey -> cmp/unexpected-arm by default",
    await codeOf(mk([H.ip(0, 0, certDer, { privateKey: privBlob })]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/unexpected-arm");
  // With the opt-in the grant is accepted and the container is opened with the session's own
  // credential. This one is not a key package, so the delivery fails rather than the arm.
  check("51a. with opts.acceptCentralKeyGeneration the arm is accepted and the container is opened",
    await codeOf(mk([H.ip(0, 0, certDer, { privateKey: privBlob })], { acceptCentralKeyGeneration: true })
      .session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-key-package");
  check("51b. and the opt-in is a boolean, not any truthy value",
    codeOfSync(function () {
      return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
        transport: function () { return Promise.resolve({ responseBytes: Buffer.alloc(0), status: 200 }); },
        acceptCentralKeyGeneration: "yes" });
    }) === "cmp/bad-input");

  // The request half (sec. 4.1.6): an entity that cannot generate a key omits certTemplate.publicKey
  // and sends no proof of possession, since it holds no key to prove possession of. RFC 9480 sec. 2.20
  // then requires cmp2021 in the header of that first request, because the response carries an
  // EnvelopedData.
  var kgaDelivery = await H.centralKeyGeneration(pki, CLIENT);
  var s51c = mk([H.ip(0, 0, kgaDelivery.deliveredCert, { privateKey: kgaDelivery.container }), H.pkiconf()],
    { acceptCentralKeyGeneration: true });
  var r51c = await s51c.session.enroll(H.irCentralRequest(pki));
  check("51c. a central key generation request delivers the key, paired with the issued certificate",
    r51c.outcome === "issued" && !!r51c.deliveredKey && r51c.deliveredKey.keys.length === 1 &&
    r51c.deliveredKey.keys[0].equals(kgaDelivery.deliveredKey) && r51c.deliveredKey.trusted === true &&
    r51c.certificate.equals(kgaDelivery.deliveredCert));
  var sent51c = pki.schema.cmp.parse(s51c.transport.calls[0].body);
  check("51c2. and that request carries cmp2021 and no proof of possession",
    sent51c.header.pvno === 3 &&
    pki.schema.crmf.parse(sent51c.body.bytes).messages[0].popo === null);
  check("51c3. the other permitted request shape, a zero-length subjectPublicKey, works the same way",
    (await mk([H.ip(0, 0, kgaDelivery.deliveredCert, { privateKey: kgaDelivery.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true }).session.enroll(H.irCentralRequest(pki, true))).outcome === "issued");
  check("51c4. a central key generation request without the opt-in is refused before it is sent",
    await codeOf(mk([H.ip(0, 0, certDer)]).session.enroll(H.irCentralRequest(pki))) === "cmp/bad-input");
  check("51c5. and one carrying a proof of possession is refused: there is no key to prove",
    await codeOf(mk([H.ip(0, 0, certDer)], { acceptCentralKeyGeneration: true })
      .session.enroll({ ir: { certTemplate: { subject: [{ commonName: "leaf" }] }, pop: { type: "raVerified", raVerified: true } } })) === "cmp/bad-input");
  // The authority's signature says the key package is authentic and says nothing about which
  // certificate it belongs with, so the pair is checked before the grant is confirmed.
  check("51c6. a certificate that does not certify the delivered key is refused, not confirmed",
    await codeOf(mk([H.ip(0, 0, certDer, { privateKey: kgaDelivery.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true }).session.enroll(H.irCentralRequest(pki))) === "cmp/bad-key-package");
  // The pair is decided from the private material, not from the public point the key structure states
  // about itself: a key whose scalar was replaced while its stored point was left alone matches the
  // certificate on paper and cannot use it.
  var kgaSwapped = await H.centralKeyGeneration(pki, CLIENT, { swapScalar: true });
  check("51c7. a delivered key whose stored public point is not the one its scalar generates is refused",
    await codeOf(mk([H.ip(0, 0, kgaSwapped.deliveredCert, { privateKey: kgaSwapped.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true }).session.enroll(H.irCentralRequest(pki))) === "cmp/bad-key-package");
  // The same for RSA, where the modulus and public exponent are part of the private structure and no
  // amount of stripping makes a derivation come from the private components.
  var kgaRsa = await H.centralKeyGeneration(pki, CLIENT, { rsa: true });
  check("51c8. an RSA delivery is accepted when its two halves are a pair",
    (await mk([H.ip(0, 0, kgaRsa.deliveredCert, { privateKey: kgaRsa.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true }).session.enroll(H.irCentralRequest(pki))).outcome === "issued");
  var kgaBroken = await H.centralKeyGeneration(pki, CLIENT, { rsa: true, breakPrivate: true });
  check("51c9. and refused when its private components cannot use the modulus it states",
    await codeOf(mk([H.ip(0, 0, kgaBroken.deliveredCert, { privateKey: kgaBroken.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true }).session.enroll(H.irCentralRequest(pki))) === "cmp/bad-key-package");

  check("51d. an enrollment that delivered no key reports none",
    (await mk([H.ip(0, 0, certDer), H.pkiconf()], { acceptCentralKeyGeneration: true })
      .session.enroll(H.irRequest(CLIENT.spki))).deliveredKey === null);
  // The authority is authorized against the session's anchors, so one this session does not trust is
  // refused even though the container itself is well formed.
  var kgaForeign = await H.centralKeyGeneration(pki, CLIENT, { foreign: true });
  check("51e. an authority outside the session's anchors does not deliver a key",
    await codeOf(mk([H.ip(0, 0, kgaForeign.deliveredCert, { privateKey: kgaForeign.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true }).session.enroll(H.irCentralRequest(pki))) === "cmp/unauthorized-kga");
  // A shared-secret session reaches the password technique (sec. 4.1.6.3), and holds the authority to
  // the anchors it was given rather than to the secret alone when it has them.
  var KGA_MAC_SECRET = "shared-secret-central-keygen";
  var kgaMac = await H.centralKeyGeneration(pki, CLIENT, { password: KGA_MAC_SECRET });
  var s51f = pki.cmp.session({ url: URL, mac: { secret: KGA_MAC_SECRET },
    transport: H.fakeCa(pki, [H.ip(0, 0, kgaMac.deliveredCert, { privateKey: kgaMac.container }), H.pkiconf()],
      { macSecret: KGA_MAC_SECRET }).transport,
    sleep: function () { return Promise.resolve(); },
    acceptCentralKeyGeneration: true, trustAnchors: [kgaMac.anchor] });
  var r51f = await s51f.enroll(H.irCentralRequest(pki));
  check("51f. a shared-secret session opens the password-technique container it was sent",
    r51f.outcome === "issued" && !!r51f.deliveredKey &&
    r51f.deliveredKey.keys[0].equals(kgaMac.deliveredKey) && r51f.deliveredKey.trusted === true);
  // With no anchors a shared-secret session has nothing to chain to, so it authorizes the authority
  // by the secret, which sec. 4.1.6 permits a MAC-protected exchange, and says the chain is unproven.
  var s51g = pki.cmp.session({ url: URL, mac: { secret: KGA_MAC_SECRET },
    transport: H.fakeCa(pki, [H.ip(0, 0, kgaMac.deliveredCert, { privateKey: kgaMac.container }), H.pkiconf()],
      { macSecret: KGA_MAC_SECRET }).transport,
    sleep: function () { return Promise.resolve(); }, acceptCentralKeyGeneration: true });
  var r51g = await s51g.enroll(H.irCentralRequest(pki));
  check("51g. and with no anchors it authorizes by the secret, reporting the chain unproven",
    r51g.outcome === "issued" && !!r51g.deliveredKey && r51g.deliveredKey.trusted === false);
  // The technique follows the request's protection: a signature session holds a private key and does
  // not open a password container, whatever the authority sent.
  check("51h. a signature session does not open a password-technique container",
    await codeOf(mk([H.ip(0, 0, kgaMac.deliveredCert, { privateKey: kgaMac.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true })
      .session.enroll(H.irCentralRequest(pki))) === "cmp/bad-key-package");

  // A central key generation transaction submits no key for the grant to be held to, so a grant that
  // carries only a certificate is bound to nothing and must not be confirmed.
  check("51h0. a central key generation grant that carries no delivered key is refused",
    await codeOf(mk([H.ip(0, 0, certDer), H.pkiconf()], { acceptCentralKeyGeneration: true })
      .session.enroll(H.irCentralRequest(pki))) === "cmp/bad-cert-response");
  // A request refused while it was being built leaves the session retryable, and the retry's own
  // binding governs: an ordinary request after a central one is an ordinary transaction.
  var s51n = mk([H.ip(0, 3), H.pollRep(0, 1), H.pollRep(0, 1)], { acceptCentralKeyGeneration: true, maxPolls: 2 });
  await codeOf(s51n.session.enroll({ ir: { certTemplate: { subject: [{ commonName: "leaf" }] }, bogusField: 1 } }));
  var tok51n = (await s51n.session.enroll(H.irRequest(CLIENT.spki))).resumeToken;
  check("51n. a retry after a refused central request carries the retry's own binding, not the first's",
    tok51n != null && tok51n.centralKeyGeneration === false && tok51n.requestedSpki !== null);

  // Reading the caller's request object runs whatever accessors it carries, and one of those can call
  // back into the session. The transaction slot is claimed before any of that is read, so the
  // re-entrant call is refused rather than opening a second transaction whose state the first would
  // then write over.
  var s51o = mk([H.ip(0, 0, certDer), H.pkiconf()], { acceptCentralKeyGeneration: true });
  var innerCode = null;
  var reentrant = { ir: { certTemplate: { subject: [{ commonName: "leaf" }] } } };
  Object.defineProperty(reentrant.ir, "key", {
    enumerable: true,
    get: function () {
      if (innerCode === null) {
        innerCode = "pending";
        s51o.session.enroll(H.irRequest(CLIENT.spki)).then(
          function () { innerCode = "NO-THROW"; },
          function (e) { innerCode = (e && e.code) || "RAW"; });
      }
      return null;
    },
  });
  await codeOf(s51o.session.enroll(reentrant));
  await new Promise(function (r) { setImmediate(r); });
  check("51o. a request whose accessor re-enters the session is refused a second transaction",
    innerCode === "cmp/bad-input");

  // The request that goes on the wire is the one the checks were applied to. An accessor that answers
  // once for the classification and then swaps the arm for a central one cannot make the session send
  // a request it never admitted: it sends the copy it read, so the grant stays bound to the key the
  // caller submitted.
  var s51p = mk([H.ip(0, 0, certDer), H.pkiconf()], { acceptCentralKeyGeneration: true });
  var swapArm = { ir: { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: CLIENT.spki } } };
  Object.defineProperty(swapArm.ir, "certReqId", {
    enumerable: true,
    get: function () { swapArm.ir = { certTemplate: {}, key: null }; return 0; },
  });
  var r51p = await s51p.session.enroll(swapArm);
  var sent51p = pki.schema.cmp.parse(s51p.transport.calls[0].body);
  var sentTemplate = pki.schema.crmf.parse(sent51p.body.bytes).messages[0].certReq.certTemplate;
  check("51p. an arm swapped after it was classified is not the arm that is sent",
    r51p.outcome === "issued" && sent51p.header.pvno === 2 &&
    sentTemplate.publicKey != null && sentTemplate.publicKey.publicKey.bytes.length > 0);

  // A session certificate option takes DER, PEM, or an already-parsed certificate. The KGA chain is
  // built from the same pool, so an intermediate given in any of the three reaches it.
  var kgaDeep = await H.centralKeyGeneration(pki, CLIENT, { viaIntermediate: true });
  for (var interForm of [["DER", kgaDeep.intermediate], ["PEM", pki.schema.x509.pemEncode(kgaDeep.intermediate, "CERTIFICATE")],
    ["a parsed certificate", pki.schema.x509.parse(kgaDeep.intermediate)]]) {
    check("51h4. an authority under an intermediate given as " + interForm[0] + " delivers the key",
      (await mk([H.ip(0, 0, kgaDeep.deliveredCert, { privateKey: kgaDeep.container }), H.pkiconf()],
        { acceptCentralKeyGeneration: true, intermediates: [interForm[1]] })
        .session.enroll(H.irCentralRequest(pki))).outcome === "issued");
  }
  check("51h5. and without the intermediate the authority's chain cannot be built",
    await codeOf(mk([H.ip(0, 0, kgaDeep.deliveredCert, { privateKey: kgaDeep.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true }).session.enroll(H.irCentralRequest(pki))) === "cmp/unauthorized-kga");
  // The anchor pool takes the same three forms, plus the { name, publicKey, algorithm } tuple that is
  // what an anchor without a certificate looks like. Each reaches the authority's chain.
  for (var anchorForm of [["DER", H.caCert], ["PEM", pki.schema.x509.pemEncode(H.caCert, "CERTIFICATE")],
    ["a parsed certificate", pki.schema.x509.parse(H.caCert)]]) {
    check("51h6. an anchor given as " + anchorForm[0] + " authorizes the authority",
      (await mk([H.ip(0, 0, kgaDelivery.deliveredCert, { privateKey: kgaDelivery.container }), H.pkiconf()],
        { acceptCentralKeyGeneration: true, trustAnchors: [anchorForm[1]] })
        .session.enroll(H.irCentralRequest(pki))).outcome === "issued");
  }
  var caParsed = pki.schema.x509.parse(H.caCert);
  check("51h7. and an anchor tuple, which names a key rather than a certificate, reaches it too",
    (await mk([H.ip(0, 0, kgaDelivery.deliveredCert, { privateKey: kgaDelivery.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true, trustAnchors: [{ name: caParsed.subject,
        publicKey: caParsed.subjectPublicKeyInfo.bytes,
        algorithm: caParsed.subjectPublicKeyInfo.algorithm.oid }] })
      .session.enroll(H.irCentralRequest(pki))).outcome === "issued");

  // A session that names the instant it validates at judges the authority's chain at that instant too,
  // rather than one certificate at a stated time and another at now.
  var kgaExpired = await H.centralKeyGeneration(pki, CLIENT, { notAfter: new Date("2021-01-01T00:00:00Z") });
  check("51h2. an authority whose certificate expired before opts.time does not deliver a key",
    await codeOf(mk([H.ip(0, 0, kgaExpired.deliveredCert, { privateKey: kgaExpired.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true, time: new Date("2022-01-01T00:00:00Z") })
      .session.enroll(H.irCentralRequest(pki))) === "cmp/unauthorized-kga");
  check("51h3. and the same authority delivers it at an instant its certificate covers",
    (await mk([H.ip(0, 0, kgaExpired.deliveredCert, { privateKey: kgaExpired.container }), H.pkiconf()],
      { acceptCentralKeyGeneration: true, time: new Date("2020-06-01T00:00:00Z") })
      .session.enroll(H.irCentralRequest(pki))).outcome === "issued");

  // A central key generation transaction that outlives its process resumes like any other, held to
  // the delivered key rather than to a requested one, which is the binding it never had.
  var s51i = mk([H.ip(0, 3), H.pollRep(0, 1), H.pollRep(0, 1)], { acceptCentralKeyGeneration: true, maxPolls: 2 });
  var tok51 = (await s51i.session.enroll(H.irCentralRequest(pki))).resumeToken;
  check("51i. its resume token names central key generation and no requested key",
    tok51 != null && tok51.centralKeyGeneration === true && tok51.requestedSpki === null);
  // Every leg of the transaction expects the EnvelopedData grant, so every leg carries the version.
  check("51i2. and every poll it sent carries cmp2021, not just the initial request",
    s51i.transport.calls.length > 1 && s51i.transport.calls.every(function (c) {
      return pki.schema.cmp.parse(c.body).header.pvno === 3;
    }));
  var kgaResume = await H.centralKeyGeneration(pki, CLIENT);
  var s51jf = H.fakeCa(pki, [H.pollRep(0, 1),
    H.ip(0, 0, kgaResume.deliveredCert, { privateKey: kgaResume.container }), H.pkiconf()]);
  var s51j = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
    transport: s51jf.transport, sleep: function () { return Promise.resolve(); },
    acceptCentralKeyGeneration: true });
  var r51j = await s51j.resumePoll(tok51);
  check("51j. and the resumed poll delivers the key and pairs it with the issued certificate",
    r51j.outcome === "issued" && !!r51j.deliveredKey &&
    r51j.deliveredKey.keys[0].equals(kgaResume.deliveredKey));
  check("51j2. the resumed process carries the version on every leg it sends too",
    s51jf.transport.calls.length > 1 && s51jf.transport.calls.every(function (c) {
      return pki.schema.cmp.parse(c.body).header.pvno === 3;
    }));
  // resumePoll reads the token before it sends anything, so a refused token never reaches the wire.
  check("51k. a session without the opt-in refuses to resume such a transaction",
    await codeOf(mk([H.pollRep(0, 1)]).session.resumePoll(tok51)) === "cmp/bad-input");
  check("51l. a token naming both a requested key and central key generation is refused",
    await codeOf(mk([H.pollRep(0, 1)], { acceptCentralKeyGeneration: true }).session.resumePoll(
      Object.assign({}, tok51, { requestedSpki: Buffer.from(CLIENT.spki).toString("base64") }))) === "cmp/bad-input");
  check("51m. and one naming neither is still refused, since the grant would bind to nothing",
    await codeOf(mk([H.pollRep(0, 1)], { acceptCentralKeyGeneration: true }).session.resumePoll(
      Object.assign({}, tok51, { centralKeyGeneration: false }))) === "cmp/bad-input");

  // ===== 52. the cached signer tracks the MOST RECENT rotation: A(waiting) -> B(grant) -> B(pkiConf, no extraCerts) =====
  var s52f = H.fakeCa(pki, [H.ip(0, 3), { body: H.ip(0, 0, certDer), rotateSigner: true }, { body: H.pkiconf(), rotateSigner: true, noExtraCerts: true }]);
  var s52 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s52f.transport, sleep: function () { return Promise.resolve(); } });
  var r52 = await s52.enroll(H.irRequest(CLIENT.spki));
  check("52. the fallback uses the most recently verified signer (B), not the first (A) -> issued", r52.outcome === "issued" && r52.confirmed === true);

  // ===== 53. a keyless ir (no certTemplate.publicKey, e.g. a raVerified request) is refused at the session boundary =====
  check("53. an ir without a submitted public key -> cmp/bad-input (a session enrolls a client-generated key)",
    await codeOf(mk([H.pkiconf()]).session.enroll({ ir: { certTemplate: { subject: [{ commonName: "x" }] } } })) === "cmp/bad-input");

  // ===== 54. an issued cert with an UNRECOGNIZED signature algorithm -> the certConf hash is indeterminate -> reject =====
  var unkCert = await H.makeUnknownSigAlgCert(pki, CLIENT.spki);
  check("54. an unrecognized signature-algorithm OID (no resolvable hash) -> cmp/bad-cert-response (not a guessed SHA-256)",
    await codeOf(mk([H.ip(0, 0, unkCert), H.pkiconf()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-cert-response");

  // ===== 55. a granting response with a non-X.509 caPubs entry is rejected BEFORE the certConf =====
  var s55 = mk([{ body: H.ip(0, 0, certDer, { caPubs: [H.caCert] }), malformedCert: true, certOf: H.caCert }]);
  check("55. a non-X.509 caPubs entry -> cmp/bad-cert-response (validated before the grant is confirmed)",
    await codeOf(s55.session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-cert-response");
  check("55b. the malformed caPubs is rejected BEFORE any certConf leg is sent", s55.transport.calls.length === 1);

  // ===== 56. a REGISTERED but non-signature alg (rsaEncryption) is NOT a hashless signature -> reject, not SHA-256 =====
  var nonSigCert = await H.makeRegisteredNonSigCert(pki, CLIENT.spki);
  check("56. a registered non-signature sig-alg (rsaEncryption) -> cmp/bad-cert-response (only true hashless signatures default to SHA-256)",
    await codeOf(mk([H.ip(0, 0, nonSigCert), H.pkiconf()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-cert-response");

  // ===== 57. the transactionID getter returns a defensive copy -- a caller mutating it cannot desync the transaction =====
  var s57 = mk([H.ip(0, 0, certDer), H.pkiconf()]);
  s57.session.transactionID.fill(0);   // a caller zeroing the returned buffer must NOT corrupt the session identity
  var r57 = await s57.session.enroll(H.irRequest(CLIENT.spki));
  var reqTxid57 = pki.schema.cmp.parse(s57.transport.calls[0].body).header.transactionID;
  check("57. mutating the returned transactionID does not desync the transaction (a defensive copy is returned)",
    r57.outcome === "issued" && reqTxid57.equals(s57.session.transactionID) && !reqTxid57.every(function (x) { return x === 0; }));

  // ===== 58. an issued leaf with a CORRUPTED signature (parses + key matches, but the signature is invalid) -> reject =====
  var badSigLeaf = H.corruptLeafSig(certDer);   // structurally valid, chains by name, but the ECDSA signature no longer verifies
  check("58. an issued cert whose signature does not verify -> cmp/bad-cert-response (path-validated before certConf, not just parsed)",
    await codeOf(mk([H.ip(0, 0, badSigLeaf), H.pkiconf()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-cert-response");

  // ===== 59. a SINGLETON (non-array) trustAnchors -- a form the constructor accepts -- is normalized for leaf validation =====
  var s59f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()]);
  var s59 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: H.caCert, transport: s59f.transport, sleep: function () { return Promise.resolve(); } });
  var r59 = await s59.enroll(H.irRequest(CLIENT.spki));
  check("59. a single-certificate trustAnchors (not an array) is normalized before leaf validation -> issued", r59.outcome === "issued");

  // ===== 60. the certConf PSS hash dispatches by the IMMUTABLE param OID -- a pki.oid.register rename cannot break it =====
  var pss60 = await H.makePssCert(pki, CLIENT.spki);   // built before the rename
  var sha384Oid = pki.oid.byName("sha384");
  pki.oid.register(sha384Oid, "renamed-sha384");
  try {
    var s60 = mk([H.ip(0, 0, pss60.cert), H.pkiconf()], { trustAnchors: [H.caCert, pss60.ca] });
    var r60 = await s60.session.enroll(H.irRequest(CLIENT.spki));
    check("60. a PSS certConf hash resolves by the param OID even when 'sha384' is renamed via pki.oid.register -> issued", r60.outcome === "issued");
  } finally { pki.oid.register(sha384Oid, "sha384"); }

  // ===== 61. an UNSOLICITED implicitConfirm (the caller did not request it) is ignored -> the explicit certConf runs =====
  var s61f = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), generalInfo: H.IMPLICIT_CONFIRM_GI }, H.pkiconf()]);
  var s61 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s61f.transport, sleep: function () { return Promise.resolve(); } });   // implicitConfirm NOT requested
  var r61 = await s61.enroll(H.irRequest(CLIENT.spki));
  check("61. an unsolicited implicitConfirm is not honored -> issued via an explicit certConf (implicitConfirm false, two legs)",
    r61.outcome === "issued" && r61.implicitConfirm === false && r61.confirmed === true && s61f.transport.calls.length === 2);

  // ===== 62. a leaf signed by the CMP protection signer (delivered ONLY in extraCerts) validates via the cached signer =====
  var siLeaf = await H.makeSignerIssuedLeaf(pki, CLIENT.spki);
  var s62f = H.fakeCa(pki, [H.ip(0, 0, siLeaf), H.pkiconf()], { issuerSigner: true });
  var s62 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s62f.transport, sleep: function () { return Promise.resolve(); } });
  var r62 = await s62.enroll(H.irRequest(CLIENT.spki));
  check("62. a leaf whose issuer is the CMP signer (only in extraCerts) validates via the cached signer in the pool -> issued", r62.outcome === "issued");

  // ===== 63. a COMPOSITE-signature issued cert -> the certConf resolves a hash (SHA-256 + explicit hashAlg), not indeterminate =====
  var compLeaf = await H.makeCompositeSigOidCert(pki, CLIENT.spki);
  var s63f = H.fakeCa(pki, [H.ip(0, 0, compLeaf), H.pkiconf()], { macSecret: "s3cr3t-63" });   // a MAC session skips leaf path-validation, reaching the certConf-hash resolver
  var s63 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-63" }, transport: s63f.transport, sleep: function () { return Promise.resolve(); } });
  var r63 = await s63.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key));
  var cc63 = pki.schema.cmp.parse(s63f.transport.calls[1].body).body.decoded[0];
  check("63. a composite signature algorithm -> certConf under SHA-256 with an explicit hashAlg (not cmp/bad-cert-response)", r63.outcome === "issued" && cc63.hashAlg != null);

  // ===== 64. a signer chained through an INTERMEDIATE (delivered only in the first leg's extraCerts): a later =====
  //          leg that omits extraCerts still verifies -- the cached CHAIN (not just the signer) rebuilds the path.
  var s64f = H.fakeCa(pki, [H.ip(0, 0, certDer), { body: H.pkiconf(), noExtraCerts: true }], { deepSigner: true });
  var s64 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s64f.transport, sleep: function () { return Promise.resolve(); } });
  var r64 = await s64.enroll(H.irRequest(CLIENT.spki));
  check("64. a later leg omitting extraCerts rebuilds the signer path via the cached intermediate chain -> issued", r64.outcome === "issued" && r64.confirmed === true);

  // ===== 65. the issued leaf is signed by the intermediate (delivered in the grant's extraCerts) -> leaf validation uses the cached chain =====
  var intLeaf = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // leaf -> intermediate -> root
  var s65f = H.fakeCa(pki, [H.ip(0, 0, intLeaf), H.pkiconf()], { deepSigner: true });   // extraCerts = [signer, intermediate]
  var s65 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s65f.transport, sleep: function () { return Promise.resolve(); } });
  var r65 = await s65.enroll(H.irRequest(CLIENT.spki));
  check("65. a leaf issued by the intermediate validates via the cached chain material in the leaf pool -> issued", r65.outcome === "issued");

  // ===== 66. a SHA-512 composite -> the certConf uses the composite's DECLARED prehash (SHA-512), not a hardcoded SHA-256 =====
  var comp512 = await H.makeCompositeSigOidCert(pki, CLIENT.spki, "id-MLDSA65-ECDSA-P256-SHA512");
  var s66f = H.fakeCa(pki, [H.ip(0, 0, comp512), H.pkiconf()], { macSecret: "s3cr3t-66" });
  var s66 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-66" }, transport: s66f.transport, sleep: function () { return Promise.resolve(); } });
  var r66 = await s66.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key));
  var cc66 = pki.schema.cmp.parse(s66f.transport.calls[1].body).body.decoded[0];
  var wantH66 = require("node:crypto").createHash("sha512").update(comp512).digest();
  check("66. a SHA-512 composite -> certConf certHash under SHA-512 with hashAlg sha512 (the composite's own prehash)",
    r66.outcome === "issued" && Buffer.from(cc66.certHash).equals(wantH66));

  // ===== 67. a malformed (non-X.509) entry in the grant's extraCerts is dropped from the cache, not fed to path.build =====
  var s67f = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), badExtraCert: true }, H.pkiconf()]);
  var s67 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s67f.transport, sleep: function () { return Promise.resolve(); } });
  var r67 = await s67.enroll(H.irRequest(CLIENT.spki));
  check("67. a malformed extraCerts entry (bounded by verify) is not cached into the leaf pool -> the valid grant issues", r67.outcome === "issued");

  // ===== 68. an rsaEncryption request SPKI OMITTING the NULL param matches an issued cert carrying the NULL (canonical key match) =====
  var rsaKp = require("node:crypto").generateKeyPairSync("rsa", { modulusLength: 2048 });
  var rsaKey = rsaKp.privateKey.export({ format: "der", type: "pkcs8" });
  var rsaWithNull = rsaKp.publicKey.export({ format: "der", type: "spki" });   // node emits WITH the NULL param
  var rsaNoNull = H.stripSpkiParams(pki, rsaWithNull);                          // the same key, NULL param omitted
  var rsaEe = await H.makeCaSignedLeaf(pki, rsaWithNull, "rsa-ee");             // the enrolling entity cert (request protection)
  var rsaLeaf = await H.makeCaSignedLeaf(pki, rsaWithNull, "rsa-issued");       // the ISSUED cert (SPKI carries the NULL)
  var s68f = H.fakeCa(pki, [H.ip(0, 0, rsaLeaf), H.pkiconf()]);
  var s68 = pki.cmp.session({ url: URL, key: rsaKey, cert: rsaEe, trustAnchors: [H.caCert], transport: s68f.transport, sleep: function () { return Promise.resolve(); } });
  var r68 = await s68.enroll({ ir: { certTemplate: { subject: [{ commonName: "rsa-issued" }], publicKey: rsaNoNull } } });
  check("68. a request SPKI with the rsaEncryption NULL omitted matches an issued cert carrying it -> issued (keys compared, not bytes)", r68.outcome === "issued");

  // ===== 69. a FLOODED extraCerts (past path.build's candidate cap) is deduped + count-capped in the cache =====
  var s69f = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), padExtraCerts: 1005 }, H.pkiconf()]);   // > PATH_BUILD_MAX_CANDIDATES if not bounded
  var s69 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s69f.transport, sleep: function () { return Promise.resolve(); } });
  var r69 = await s69.enroll(H.irRequest(CLIENT.spki));
  check("69. a flood of unsigned extraCerts is deduped + capped before caching -> the valid grant still issues (no meddler DoS)", r69.outcome === "issued");

  // ===== 70. a same-subject DECOY prepended to a later leg's unsigned extraCerts -> fall back to the cached signer =====
  var s70 = mk([H.ip(0, 0, certDer), { body: H.pkiconf(), decoyExtraCert: true }]);   // signer2 (same subject, other key) selected first
  var r70 = await s70.session.enroll(H.irRequest(CLIENT.spki));
  check("70. a same-subject decoy prepended to a later leg's unsigned extraCerts (protection fails under it) falls back to the earlier authenticated signer -> issued", r70.outcome === "issued");

  // ===== 71. an issued leaf sharing the request's key BITS but a DIFFERENT EC curve param is NOT the requested key =====
  var swappedLeaf = await H.makeCurveSwappedLeaf(pki, CLIENT.spki);   // same subjectPublicKey bits, secp384r1 OID
  var s71 = mk([H.ip(0, 0, swappedLeaf), H.pkiconf()]);
  check("71. a granted cert whose SPKI shares the requested bits but declares a different EC curve -> cmp/bad-cert-response (params are part of the key identity, not dropped)", await codeOf(s71.session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-cert-response");

  // ===== 72. a MAC-protected ir with NO arm-local POP key -> cmp/bad-input (a PBMAC1 session has no signing key) =====
  var s72f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { macSecret: "s3cr3t-72" });
  var s72 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-72" }, transport: s72f.transport, sleep: function () { return Promise.resolve(); } });
  check("72. a MAC-protected ir/cr/kur without the requested key's private half for the CRMF proof of possession -> cmp/bad-input (crmf.build would emit none)", await codeOf(s72.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-input");

  // ===== 73. an acceptCert policy can VETO a grantedWithMods certificate -> rejected + a rejecting certConf =====
  var seen73 = null;
  var s73f = H.fakeCa(pki, [H.ip(0, 1, certDer), H.pkiconf()]);   // status 1 = grantedWithMods
  var s73 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s73f.transport, sleep: function () { return Promise.resolve(); }, acceptCert: function (cert, info) { seen73 = info; return false; } });
  var r73 = await s73.enroll(H.irRequest(CLIENT.spki));
  check("73a. an acceptCert veto of a grantedWithMods cert -> outcome:rejected, still surfacing the inspected certificate", r73.outcome === "rejected" && Buffer.isBuffer(r73.certificate) && r73.certificate.equals(certDer));
  check("73b. the policy is told the grant was grantedWithMods (the cert bytes + a status name)", seen73 && seen73.grantedWithMods === true && seen73.status === "grantedWithMods");
  var cc73 = pki.schema.cmp.parse(s73f.transport.calls[1].body).body.decoded[0];   // the certConf CertStatus
  check("73c. the certConf carried a REJECTING statusInfo (status rejection) so the CA learns the EE declined", cc73.statusInfo && cc73.statusInfo.status.code === 2);

  // ===== 74. an acceptCert policy that ACCEPTS (returns true) -> issued (default behavior preserved) =====
  var s74f = H.fakeCa(pki, [H.ip(0, 1, certDer), H.pkiconf()]);
  var s74 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s74f.transport, sleep: function () { return Promise.resolve(); }, acceptCert: function () { return true; } });
  var r74 = await s74.enroll(H.irRequest(CLIENT.spki));
  check("74. an acceptCert policy returning true -> issued via an accepting certConf (no statusInfo)", r74.outcome === "issued" && r74.confirmed === true && pki.schema.cmp.parse(s74f.transport.calls[1].body).body.decoded[0].statusInfo == null);

  // ===== 75. a non-function acceptCert -> cmp/bad-input at construction (a typo cannot silently auto-accept) =====
  check("75. a non-function opts.acceptCert -> cmp/bad-input at construction (never a silently-skipped veto policy)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], acceptCert: "yes-please" }); })) === "cmp/bad-input");

  // ===== 76. a caller intermediates pool near the ceiling: the cached signer material stays BOUNDED (no path/bad-input) =====
  var s76 = mk([H.ip(0, 0, certDer), H.pkiconf()], { intermediates: DISTINCT.slice(0, 903) });   // 999 DISTINCT -> room for one added cert
  var r76 = await s76.session.enroll(H.irRequest(CLIENT.spki));
  check("76. a caller intermediates pool near the ceiling + the cached signer material bounded to the remaining room -> the valid grant still issues (a meddler cannot fail it)", r76.outcome === "issued");

  // ===== 77. acceptCert + implicitConfirm together -> cmp/bad-input at construction (a veto has no reject leg) =====
  check("77. opts.acceptCert combined with opts.implicitConfirm -> cmp/bad-input at construction (implicit confirmation leaves no certConf to reject on)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], implicitConfirm: true, acceptCert: function () { return true; } }); })) === "cmp/bad-input");

  // ===== 78. an authenticated caPubs is bounded against the ceiling too (a valid caller pool + a delivered caPubs must not fail) =====
  var s78 = mk([H.ip(0, 0, certDer, { caPubs: [H.caCert] }), H.pkiconf()], { intermediates: DISTINCT });   // 1000 DISTINCT AT the ceiling; an unbounded caPubs append would push it over
  var r78 = await s78.session.enroll(H.irRequest(CLIENT.spki));
  check("78. a caller intermediates pool near the ceiling + an authenticated caPubs -> caPubs bounded to the remaining room, the valid grant still issues", r78.outcome === "issued");

  // ===== 79. the fallback signer-chain pool is bounded too (a large caller pool + a signer-omitting later leg must not fail) =====
  var s79 = mk([H.ip(0, 0, certDer), { body: H.pkiconf(), noExtraCerts: true }], { intermediates: DISTINCT });   // 1000 DISTINCT AT the ceiling; leg 2 omits its signer -> fallback to the cached chain
  var r79 = await s79.session.enroll(H.irRequest(CLIENT.spki));
  check("79. a caller intermediates pool at the ceiling + a later leg that omits its signer -> the fallback cached chain is bounded, the transaction still confirms", r79.outcome === "issued");

  // ===== 80. a SHAKE256-prehash composite issued cert -> the certConf hash is indeterminate (never silently SHA-256) =====
  var shakeLeaf = await H.makeCompositeSigOidCert(pki, CLIENT.spki, "id-MLDSA87-Ed448-SHAKE256");
  var s80f = H.fakeCa(pki, [H.ip(0, 0, shakeLeaf), H.pkiconf()], { macSecret: "s3cr3t-80" });   // MAC skips leaf path-validation, reaching the certConf-hash resolver
  var s80 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-80" }, transport: s80f.transport, sleep: function () { return Promise.resolve(); } });
  check("80. a composite whose prehash is SHAKE256 (not certConf-representable) -> cmp/bad-cert-response (never a SHA-256 certHash contradicting the signature)", await codeOf(s80.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key))) === "cmp/bad-cert-response");

  // ===== 81. the fallback intermediate capacity excludes the signer itself (a 999-pool deepSigner leg must not truncate the real issuer) =====
  var s81f = H.fakeCa(pki, [H.ip(0, 0, certDer), { body: H.pkiconf(), noExtraCerts: true }], { deepSigner: true });
  var s81 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: DISTINCT.slice(0, 903), transport: s81f.transport, sleep: function () { return Promise.resolve(); } });   // 999 DISTINCT -> room for exactly one added cert (must be the intermediate, not the already-passed signer)
  var r81 = await s81.enroll(H.irRequest(CLIENT.spki));
  check("81. a 999-cert caller pool + a signer-omitting deepSigner leg -> the one fallback slot keeps the real intermediate (the signer is excluded), still confirms", r81.outcome === "issued");

  // ===== 82. a leg that verifies only via the cached-signer FALLBACK must not overwrite the trusted cached chain =====
  //          with its own (untrusted) extraCerts -- else a meddler's decoy pool discards the real intermediate.
  var s82f = H.fakeCa(pki, [H.ip(0, 3), { body: H.pollRep(0, 1), deepDecoyExtra: true }, { body: H.ip(0, 0, certDer), noExtraCerts: true }, H.pkiconf()], { deepSigner: true });
  var s82 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s82f.transport, sleep: function () { return Promise.resolve(); } });
  var r82 = await s82.enroll(H.irRequest(CLIENT.spki));
  check("82. a fallback-verified leg (a decoy in its extraCerts) does not replace the trusted cached chain -> a later signer-omitting leg still chains via the preserved intermediate -> issued", r82.outcome === "issued");

  // ===== 83. a MAC session MAY carry trustAnchors to validate the ISSUED certificate (not the response protection) =====
  var s83f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { macSecret: "s3cr3t-83" });
  var s83 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-83" }, trustAnchors: [H.caCert], transport: s83f.transport, sleep: function () { return Promise.resolve(); } });
  var r83 = await s83.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key));
  check("83. a MAC session with trustAnchors validates the issued certificate's signature + chain (a good leaf still issues; anchors are NOT forwarded to the MAC response verify)", r83.outcome === "issued");

  // ===== 84. a caller intermediate supplied as PEM dedups against a byte-identical DER caPubs (no wasted slot) =====
  var intLeaf84 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // leaf -> intermediate -> root
  var filler84 = DISTINCT.slice(0, 902).concat([pki.schema.x509.pemEncode(certDer, "CERTIFICATE")]);   // 998 DISTINCT + certDer as PEM (999th) -- a caPubs DER duplicates the PEM
  var s84f = H.fakeCa(pki, [H.ip(0, 0, intLeaf84, { caPubs: [certDer, H.intCaCert] }), H.pkiconf()]);   // caPubs: [dup-of-PEM, the needed intermediate]
  var s84 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: filler84, transport: s84f.transport, sleep: function () { return Promise.resolve(); } });
  var r84 = await s84.enroll(H.irRequest(CLIENT.spki));
  check("84. a PEM caller intermediate dedups against a byte-identical DER caPubs -> the freed slot holds the real intermediate, the intermediate-signed leaf validates -> issued", r84.outcome === "issued");

  // ===== 85. session.transcript returns a defensive SNAPSHOT (copied bytes, a fresh array per read) =====
  var s85 = mk([H.ip(0, 0, certDer), H.pkiconf()]);
  var r85 = await s85.session.enroll(H.irRequest(CLIENT.spki));
  var orig85 = r85.transcript[0].bytes[0];
  r85.transcript[0].bytes[0] ^= 0xff;   // mutate the returned snapshot's byte buffer
  check("85a. the transcript is a snapshot -> mutating a returned entry's bytes does not affect the internal transcript", s85.session.transcript[0].bytes[0] === orig85);
  var read85a = s85.session.transcript, read85b = s85.session.transcript;   // two reads -> two distinct arrays
  check("85b. session.transcript returns a fresh array each read (freezing the returned value is harmless)", read85a !== read85b && Object.isFrozen(Object.freeze(read85a)) && read85b.length === 4);
  // A request leg records no verdict -- nothing has been verified yet. The snapshot asks whether
  // the entry carries one of its own, so a value inherited from a polluted prototype is not
  // copied in and read back as a protection result this session never reached.
  Object.prototype.verdict = { valid: true, trusted: true, code: null };
  var read85c;
  try { read85c = s85.session.transcript; } finally { delete Object.prototype.verdict; }
  check("85c. an inherited verdict is not copied onto a request leg of the transcript",
    read85c[0].direction === "out" && !Object.hasOwn(read85c[0], "verdict") &&
    Object.hasOwn(read85c[1], "verdict") && read85c[1].verdict.valid === true);

  // ===== 86. a decoy carrying the real signer's key under an UNTRUSTED root (valid but untrusted) -> fall back to the cached signer =====
  var s86 = mk([H.ip(0, 0, certDer), { body: H.pkiconf(), untrustedDecoy: true }]);
  var r86 = await s86.session.enroll(H.irRequest(CLIENT.spki));
  check("86. an untrusted-issuer decoy with the signer's own key (verifies but is untrusted) -> falls back to the earlier trusted signer -> issued", r86.outcome === "issued");

  // ===== 87. a corrupted-sig copy of an issuer sharing the valid issuer's TBS must NOT evict the valid one in the dedup =====
  var intLeaf87 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // leaf -> intCaCert -> root
  var filler87 = [H.corruptLeafSig(H.intCaCert)].concat(DISTINCT.slice(0, 902));   // a corrupted-signature intCaCert (same TBS) FIRST + 998 DISTINCT = 999; room for one added cert
  var s87f = H.fakeCa(pki, [H.ip(0, 0, intLeaf87, { caPubs: [H.intCaCert] }), H.pkiconf()]);   // the VALID intCaCert delivered in caPubs
  var s87 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: filler87, transport: s87f.transport, sleep: function () { return Promise.resolve(); } });
  var r87 = await s87.enroll(H.irRequest(CLIENT.spki));
  check("87. a corrupted-sig issuer copy (same TBS) does not evict the valid issuer in the pool dedup -> the intermediate-signed leaf still validates -> issued", r87.outcome === "issued");

  // ===== 88. the issued certificate + chain are independent defensive COPIES (mutating one cannot reach session state) =====
  var s88 = mk([H.ip(0, 0, certDer), H.pkiconf()]);
  var r88 = await s88.session.enroll(H.irRequest(CLIENT.spki));
  var origLeaf88 = r88.chain[0][0];
  r88.certificate[0] ^= 0xff;   // mutate the returned certificate
  check("88. result.certificate is an independent copy -> mutating it does not affect result.chain[0] (nor internal state)", r88.chain[0][0] === origLeaf88 && r88.certificate[0] !== origLeaf88);

  // ===== 89. a decoy carrying the real signer's key under a WRONG subject (verifies but sender-mismatched) -> fall back =====
  var s89 = mk([H.ip(0, 0, certDer), { body: H.pkiconf(), wrongSubjectDecoy: true }]);
  var r89 = await s89.session.enroll(H.irRequest(CLIENT.spki));
  check("89. a wrong-subject decoy with the signer's own key (verifies but the sender does not bind) -> falls back to the cached signer -> issued", r89.outcome === "issued");

  // ===== 90. a non-boolean implicitConfirm -> cmp/bad-input at construction (a truthy string cannot reverse the policy) =====
  check("90. a non-boolean opts.implicitConfirm (a truthy string) -> cmp/bad-input at construction (never a silently-reversed confirmation policy)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], implicitConfirm: "false" }); })) === "cmp/bad-input");

  // ===== 91. an issued rsaEncryption cert with a MALFORMED parameter (empty OCTET STRING, not NULL/absent) is not the requested key =====
  var RSA = signing.makeSigner("rsa", { cn: "rsa-client" });   // rsaEncryption SPKI (NULL parameter)
  var malformedRsaLeaf = await H.makeMalformedRsaParamCert(pki, RSA.spki);   // same key bits, parameter = empty OCTET STRING
  var s91f = H.fakeCa(pki, [H.ip(0, 0, malformedRsaLeaf), H.pkiconf()], { macSecret: "s3cr3t-91" });   // MAC skips leaf path-validation, reaching the key-match
  var s91 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-91" }, transport: s91f.transport, sleep: function () { return Promise.resolve(); } });
  check("91. an issued rsaEncryption cert whose parameter is a malformed empty OCTET STRING (not NULL/absent) is NOT the requested key -> cmp/bad-cert-response", await codeOf(s91.enroll(H.irRequest(RSA.spki, null, RSA.key))) === "cmp/bad-cert-response");

  // ===== 92. a non-function opts.sleep -> cmp/bad-input at construction (never a silent fall back to the real timer) =====
  check("92. a non-function opts.sleep -> cmp/bad-input at construction (a config typo cannot silently swap the injected sleeper for the real timer)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], sleep: 5 }); })) === "cmp/bad-input");

  // ===== 93. DUPLICATE caller intermediates collapse before the capacity limit (they do not consume the ceiling) =====
  var intLeaf93 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // leaf -> intCaCert -> root
  var dup93 = [];
  for (var f93 = 0; f93 < 1000; f93++) dup93.push(H.caCert);   // 1000 COPIES of ONE cert (1 distinct) -- must NOT fill the ceiling
  var s93f = H.fakeCa(pki, [H.ip(0, 0, intLeaf93, { caPubs: [H.intCaCert] }), H.pkiconf()]);   // the required intermediate delivered ONLY in caPubs
  var s93 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: dup93, transport: s93f.transport, sleep: function () { return Promise.resolve(); } });
  var r93 = await s93.enroll(H.irRequest(CLIENT.spki));
  check("93. 1000 duplicate caller intermediates collapse to one distinct candidate before bounding -> the caPubs intermediate still fits -> the leaf validates -> issued", r93.outcome === "issued");

  // ===== 94. duplicate caller intermediates do not starve the FIRST verify's signer path (dedup before cmp.verify too) =====
  var dup94 = [];
  for (var f94 = 0; f94 < 1000; f94++) dup94.push(DISTINCT[0]);   // 1000 copies of ONE cert -> raw would fill the ceiling
  var s94f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { deepSigner: true });   // the signer chains via intCaCert delivered in its extraCerts
  var s94 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: dup94, transport: s94f.transport, sleep: function () { return Promise.resolve(); } });
  var r94 = await s94.enroll(H.irRequest(CLIENT.spki));
  check("94. 1000 duplicate caller intermediates collapse before the FIRST verify -> cmp.verify has room for the response's extraCerts issuer -> the deepSigner chains -> issued", r94.outcome === "issued");

  // ===== 95. a raVerified POP override -> cmp/bad-input (the session proves possession by signing, never raVerified) =====
  var s95f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { macSecret: "s3cr3t-95" });
  var s95 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-95" }, transport: s95f.transport, sleep: function () { return Promise.resolve(); } });
  var raReq95 = { ir: { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: CLIENT.spki }, key: CLIENT.key, pop: { type: "raVerified", raVerified: true } } };
  check("95. a MAC ir with an arm-local key BUT a raVerified POP override -> cmp/bad-input (a non-signature POP emits no proof of possession, bypassing the key requirement)", await codeOf(s95.enroll(raReq95)) === "cmp/bad-input");

  // ===== 96. caPubs delivered on a WAITING leg is retained across the poll (the eventual grant may omit it) =====
  var intLeaf96 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // leaf -> intCaCert -> root
  var s96 = mk([H.ip(0, 3, null, { caPubs: [H.intCaCert] }), H.pollRep(0, 1), H.ip(0, 0, intLeaf96), H.pkiconf()]);   // the intermediate arrives ONLY on the waiting leg
  var r96 = await s96.session.enroll(H.irRequest(CLIENT.spki));
  check("96. an intermediate delivered in a WAITING leg's caPubs is retained across the poll -> the grant that omits it still validates the intermediate-signed leaf -> issued", r96.outcome === "issued" && r96.chain.length === 2);

  // ===== 97. an invalid trustAnchors entry -> cmp/bad-input at construction (not consumed then failed at verify) =====
  check("97. a signature session with a non-certificate trustAnchors entry -> cmp/bad-input at construction (anchors validated before any request is sent)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [Buffer.from("not-a-certificate")] }); })) === "cmp/bad-input");

  // ===== 98. an invalid intermediates entry -> cmp/bad-input at construction (same class as the anchors) =====
  check("98. a session with a malformed intermediates entry -> cmp/bad-input at construction (the chain pool is validated before any request)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: [Buffer.from("garbage")] }); })) === "cmp/bad-input");

  // ===== 99. the authenticated caPubs issuer is prioritized over a ceiling-filling caller pool =====
  var intLeaf99 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // leaf -> intCaCert -> root
  var s99f = H.fakeCa(pki, [H.ip(0, 0, intLeaf99, { caPubs: [H.intCaCert] }), H.pkiconf()]);   // the needed intermediate ONLY in caPubs
  var s99 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: DISTINCT, transport: s99f.transport, sleep: function () { return Promise.resolve(); } });   // 1000 DISTINCT caller certs fill the ceiling
  var r99 = await s99.enroll(H.irRequest(CLIENT.spki));
  check("99. the authenticated caPubs intermediate is prioritized over a ceiling-filling caller pool -> the intermediate-signed leaf still validates -> issued", r99.outcome === "issued");

  // ===== 100. a MAC session with trustAnchors REJECTS an issued cert with an invalid signature =====
  var badLeaf100 = H.corruptLeafSig(certDer);   // structurally valid, INVALID signature (same SPKI -> the key-match passes)
  var s100f = H.fakeCa(pki, [H.ip(0, 0, badLeaf100), H.pkiconf()], { macSecret: "s3cr3t-100" });
  var s100 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-100" }, trustAnchors: [H.caCert], transport: s100f.transport, sleep: function () { return Promise.resolve(); } });
  check("100. a MAC session with trustAnchors rejects an issued cert whose signature is invalid -> cmp/bad-cert-response (the MAC authenticates the exchange, not the embedded cert signature)", await codeOf(s100.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key))) === "cmp/bad-cert-response");

  // ===== 101. an invalid opts.time -> cmp/bad-input at construction (not consumed then failed at verify) =====
  check("101a. a non-Date opts.time -> cmp/bad-input at construction (the verify clock is validated before any request is sent)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], time: "not-a-date" }); })) === "cmp/bad-input");
  check("101b. an Invalid Date opts.time -> cmp/bad-input at construction", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], time: new Date("nonsense") }); })) === "cmp/bad-input");

  // ===== 102. a later leg signed by a DIFFERENT trusted signer (own subject) is rejected -- the CA identity is pinned =====
  check("102a. a later leg signed by a different trusted signer (its own subject) -> cmp/untrusted-signer (pinned to the first response's CA identity)", await codeOf(mk([H.ip(0, 0, certDer), { body: H.pkiconf(), foreignSigner: true }]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/untrusted-signer");
  var s102b = mk([H.ip(0, 0, certDer), H.pkiconf()], { expectedSender: H.signerCert });   // the caller pins the CA's signer certificate
  check("102b. opts.expectedSender pinning the CA signer certificate that signs the responses -> the transaction proceeds -> issued", (await s102b.session.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");
  check("102c. opts.expectedSender pinning a DIFFERENT certificate than the response signer -> cmp/untrusted-signer (a response from a different CA is refused)", await codeOf(mk([H.ip(0, 0, certDer), H.pkiconf()], { expectedSender: H.caCert }).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/untrusted-signer");
  // opts.expectedSender binds an EMPTY-subject CA by its subjectAltName -- the case a subject-string pin reads as an unmatchable null.
  check("102d. opts.expectedSender pinning an empty-subject CA (named only by a directoryName SAN) that signs the responses -> issued (bound via the SAN, not a null subject)", (await mk([{ body: H.ip(0, 0, certDer), emptySanSigner: "a" }, { body: H.pkiconf(), emptySanSigner: "a" }], { expectedSender: H.sanSignerACert }).session.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");
  check("102e. opts.expectedSender pinning empty-subject CA A while the responses are signed by empty-subject CA B -> cmp/untrusted-signer (the SAN identities differ)", await codeOf(mk([{ body: H.ip(0, 0, certDer), emptySanSigner: "a" }, { body: H.pkiconf(), emptySanSigner: "a" }], { expectedSender: H.sanSignerBCert }).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/untrusted-signer");
  check("102f. opts.expectedSender that is not a certificate (a bare DN string) -> cmp/bad-input at construction (before the one-shot transaction engages the transport)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], expectedSender: "CN=cmp-ca.example" }); })) === "cmp/bad-input");
  // opts.expectedSender accepts the documented ALREADY-PARSED form, not only DER/PEM.
  check("102g. opts.expectedSender as an already-parsed certificate (pki.schema.x509.parse) -> the transaction proceeds -> issued (the parsed form is honored, not reparsed)", (await mk([H.ip(0, 0, certDer), H.pkiconf()], { expectedSender: pki.schema.x509.parse(H.signerCert) }).session.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");
  // The pin is what the certificate SAYS, not what the object says. This pin is compared against
  // each response signer's subject and SAN, so an edited subject would pin a different signer than
  // the caller chose -- the certificate is re-derived from the bytes it was parsed from, and it is
  // that value which is stored, so the edit never reaches the comparison.
  var pinnedEdited = pki.schema.x509.parse(H.signerCert);
  pinnedEdited.subject = pki.schema.x509.parse(H.caCert).subject;
  check("102g1. an edited subject on a pinned parsed certificate does not change who is pinned",
    (await mk([H.ip(0, 0, certDer), H.pkiconf()], { expectedSender: pinnedEdited }).session.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");
  // ...and a REBUILT pin carries no record to derive from, so it is refused at construction rather
  // than pinning something the caller cannot have meant.
  // The pool takes the same derivation as every other certificate door, so a rebuilt entry is
  // refused rather than deduped against the genuine certificate it copies -- and the refusal names
  // the entry at construction rather than letting it spend, or evict, a candidate slot.
  var poolRebuilt = Object.assign({}, pki.schema.x509.parse(H.caCert));
  check("102g3. a rebuilt pool certificate is refused, never merged onto the genuine one it copies",
    await codeOf(Promise.resolve().then(function () {
      return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
        intermediates: [H.caCert, poolRebuilt] });
    })) === "cmp/bad-input");
  // ...while the parser's own output is a perfectly good pool entry.
  check("102g4. the parser's own certificate is accepted in the pool",
    (await mk([H.ip(0, 0, certDer), H.pkiconf()], { intermediates: [pki.schema.x509.parse(H.caCert)] })
      .session.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");
  check("102g2. a rebuilt expectedSender is refused at construction",
    await codeOf(Promise.resolve().then(function () {
      return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert],
        expectedSender: Object.assign({}, pki.schema.x509.parse(H.signerCert)) });
    })) === "cmp/bad-input");
  // A first response that OMITS its extraCerts (the CA assumes the client holds its cert) resolves via the prebound expectedSender.
  check("102h. a first response omitting extraCerts + a prebound expectedSender (bytes) -> the CA cert resolves the signer -> issued (without it the signer cannot resolve)", (await mk([{ body: H.ip(0, 0, certDer), noExtraCerts: true }, H.pkiconf()], { expectedSender: H.signerCert }).session.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");
  check("102i. a first response omitting extraCerts WITHOUT a prebound signer cert -> cmp/signer-cert-not-found (the signer cannot resolve from an empty extraCerts)", await codeOf(mk([{ body: H.ip(0, 0, certDer), noExtraCerts: true }, H.pkiconf()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/signer-cert-not-found");
  check("102j. opts.expectedSender of a non-certificate type (an object that is not a parsed certificate) -> cmp/bad-input at construction", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], expectedSender: { notACertificate: true } }); })) === "cmp/bad-input");
  // A response whose extraCerts carries the signer's ISSUER but not the signer (resolved via expectedSender): the
  // override attempt must reserve ALL of extraCerts as appendable issuers (the signer is not among them), not one fewer.
  var s102k = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), stripSignerExtra: true }, H.pkiconf()], { deepSigner: true });   // extraCerts = [intCaCert] only; the deep signer resolves via expectedSender
  var sess102k = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: DISTINCT, transport: s102k.transport, expectedSender: H.deepSignerCert, sleep: function () { return Promise.resolve(); } });   // 1000 caller certs AT the ceiling
  check("102k. an extraCerts-carries-only-the-issuer response (signer via expectedSender) + a ceiling-filling caller pool -> the override reserves ALL issuer slots -> issued (reserving one fewer truncates the delivered issuer to cmp/untrusted-signer)", (await sess102k.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");
  // The same response DECLARING its signer by senderKID: nothing in extraCerts carries that identifier,
  // which is now reported as cmp/bad-sender-kid rather than a bare lookup miss. The session must still
  // fall back to the signer it already holds, and the fallback certificate is put through the same
  // identifier check, so the retry can only succeed on a certificate the message actually names.
  var s102k2 = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), stripSignerExtra: true, senderKid: H.deepSignerSki }, H.pkiconf()], { deepSigner: true });
  var sess102k2 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: DISTINCT, transport: s102k2.transport, expectedSender: H.deepSignerCert });
  check("102k2. a senderKID-declaring response whose extraCerts lack that certificate still falls back to the held signer -> issued",
    (await sess102k2.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // An EMPTY-subject signature-protection cert cannot name the requester -> opts.sender is required at construction.
  check("102l. an empty-subject signature-protection cert without opts.sender -> cmp/bad-input at construction (the empty subject cannot name the sender)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: H.sanSignerAKey, cert: H.sanSignerACert, trustAnchors: [H.caCert] }); })) === "cmp/bad-input");
  check("102m. the same empty-subject cert WITH an explicit opts.sender -> constructs (the SAN identity names the requester)", typeof pki.cmp.session({ url: URL, key: H.sanSignerAKey, cert: H.sanSignerACert, trustAnchors: [H.caCert], sender: { directoryName: [{ commonName: "san-ca-a" }] } }).enroll === "function");

  // ===== 103. opts.senderKID is propagated to every request header (PBMAC1 credential selection) =====
  var kid103 = Buffer.from([0x0a, 0x0b, 0x0c, 0x0d]);
  var s103 = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { macSecret: "s3cr3t-103" });
  var sess103 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-103" }, senderKID: kid103, transport: s103.transport, sleep: function () { return Promise.resolve(); } });
  await sess103.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key));
  var reqHdr103 = pki.schema.cmp.parse(s103.transport.calls[0].body).header;
  check("103. opts.senderKID is emitted on the request header (a CA can select the right shared secret)", Buffer.isBuffer(reqHdr103.senderKID) && reqHdr103.senderKID.equals(kid103));

  // ===== 104. opts.intermediates exceeding the candidate ceiling -> cmp/bad-input at construction =====
  check("104. opts.intermediates with more distinct certificates than the candidate ceiling -> cmp/bad-input at construction (not path/bad-input after the request is sent)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: DISTINCT.concat([certDer]) }); })) === "cmp/bad-input");

  // ===== 105. a same-identity certificate rotation (same subject, rotated key) is ALLOWED across the CA-identity pin =====
  var s105 = mk([H.ip(0, 0, certDer), { body: H.pkiconf(), rotateSigner: true }]);   // signer2: same subject, a different key
  var r105 = await s105.session.enroll(H.irRequest(CLIENT.spki));
  check("105. a same-identity certificate rotation (same subject, rotated key) across legs is allowed by the CA-identity pin -> issued", r105.outcome === "issued");

  // ===== 106. a ceiling-filling caller pool reserves room for the response's OWN extraCerts issuer (signer path) =====
  var s106f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { deepSigner: true });   // the signer chains via intCaCert delivered in its OWN extraCerts
  var s106 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: DISTINCT, transport: s106f.transport, sleep: function () { return Promise.resolve(); } });   // 1000 DISTINCT caller certs fill the ceiling
  var r106 = await s106.enroll(H.irRequest(CLIENT.spki));
  check("106. a 1000-cert distinct caller pool reserves candidate room for the deepSigner's own extraCerts issuer -> cmp.verify still chains the signer -> issued", r106.outcome === "issued");

  // ===== 107. two EMPTY-subject signers with DIFFERENT SANs across legs -> the second is rejected (pin on the authenticated SAN, not a null subject) =====
  var s107f = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), emptySanSigner: "a" }, { body: H.pkiconf(), emptySanSigner: "b" }]);
  var s107 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s107f.transport, sleep: function () { return Promise.resolve(); } });
  check("107. two empty-subject signers with different SANs across legs -> cmp/untrusted-signer (the identity pin distinguishes the authenticated SAN, not the null subject sentinel)", await codeOf(s107.enroll(H.irRequest(CLIENT.spki))) === "cmp/untrusted-signer");

  // ===== 108. certConf-hash resolver branch coverage: unknown / non-signature / hash-indeterminate algs fail closed (MAC skips leaf validation, reaching the resolver) =====
  var s108a = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-108a" }, transport: H.fakeCa(pki, [H.ip(0, 0, await H.makeUnknownSigAlgCert(pki, CLIENT.spki)), H.pkiconf()], { macSecret: "s3cr3t-108a" }).transport, sleep: function () { return Promise.resolve(); } });
  check("108a. an UNREGISTERED signature-algorithm cert (MAC session reaches the certConf-hash resolver) -> cmp/bad-cert-response", await codeOf(s108a.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key))) === "cmp/bad-cert-response");
  var s108b = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-108b" }, transport: H.fakeCa(pki, [H.ip(0, 0, await H.makeRegisteredNonSigCert(pki, CLIENT.spki)), H.pkiconf()], { macSecret: "s3cr3t-108b" }).transport, sleep: function () { return Promise.resolve(); } });
  check("108b. a registered NON-signature-algorithm cert (rsaEncryption) -> cmp/bad-cert-response (no conveyed certConf hash)", await codeOf(s108b.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key))) === "cmp/bad-cert-response");
  var s108c = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-108c" }, transport: H.fakeCa(pki, [H.ip(0, 0, await H.makePssIndeterminateCert(pki, CLIENT.spki)), H.pkiconf()], { macSecret: "s3cr3t-108c" }).transport, sleep: function () { return Promise.resolve(); } });
  check("108c. an RSASSA-PSS cert whose parameters resolve no hash (SHA-1 default) -> cmp/bad-cert-response (never a guessed SHA-256)", await codeOf(s108c.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key))) === "cmp/bad-cert-response");

  // ===== 109. implicitConfirm requested but the grant's generalInfo LACKS it -> _implicitConfirmGranted false -> an explicit certConf still runs =====
  var s109f = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), generalInfo: [{ infoType: "confirmWaitTime", infoValue: new Date(0) }] }, H.pkiconf()]);
  var s109 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], implicitConfirm: true, transport: s109f.transport, sleep: function () { return Promise.resolve(); } });
  var r109 = await s109.enroll(H.irRequest(CLIENT.spki));
  check("109. implicitConfirm requested but the grant's generalInfo carries a DIFFERENT entry -> _implicitConfirmGranted false -> an explicit certConf runs -> issued (confirmed, not implicit)", r109.outcome === "issued" && r109.confirmed === true && r109.implicitConfirm === false);

  // ===== 110. a MAC session with an EMPTY trustAnchors array treats it as ABSENT (anchors are optional for a MAC
  //            session -- used only for issued-cert validation): the leaf-chain check is skipped, exactly as with
  //            omitted anchors -> issued. An empty store reaching _engine.build would reject the leaf only in _finish,
  //            AFTER the authenticated grant consumed the one-shot session. =====
  var s110 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-110" }, trustAnchors: [], transport: H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { macSecret: "s3cr3t-110" }).transport, sleep: function () { return Promise.resolve(); } });
  check("110. a MAC session with an empty trustAnchors array treats it as absent (leaf validation skipped, as with omitted anchors) -> issued (the empty trust store would otherwise reject the leaf in _finish, after the grant consumed the one-shot session)", (await s110.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key))).outcome === "issued");

  // ===== 111-117: branch-coverage edges (recipKID, implicitConfirm-no-generalInfo, duplicate-caPubs dedup, parsed/Uint8Array/Ed25519 request forms) =====
  var kid111 = Buffer.from([0x11, 0x22]);
  var s111 = mk([H.ip(0, 0, certDer), H.pkiconf()], { recipKID: kid111 });
  await s111.session.enroll(H.irRequest(CLIENT.spki));
  check("111. opts.recipKID is emitted on the request header", Buffer.isBuffer(pki.schema.cmp.parse(s111.transport.calls[0].body).header.recipKID) && pki.schema.cmp.parse(s111.transport.calls[0].body).header.recipKID.equals(kid111));

  var s112 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], implicitConfirm: true, transport: H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()]).transport, sleep: function () { return Promise.resolve(); } });
  var r112 = await s112.enroll(H.irRequest(CLIENT.spki));
  check("112. implicitConfirm requested but the grant carries NO generalInfo -> _implicitConfirmGranted false (non-array) -> an explicit certConf runs -> issued (not implicit)", r112.outcome === "issued" && r112.implicitConfirm === false);

  var intLeaf113 = await H.makeIntSignedLeaf(pki, CLIENT.spki);
  var s113 = mk([H.ip(0, 3, null, { caPubs: [H.intCaCert] }), H.pollRep(0, 1), H.ip(0, 0, intLeaf113, { caPubs: [H.intCaCert] }), H.pkiconf()]);   // SAME intermediate on the waiting AND granting legs
  var r113 = await s113.session.enroll(H.irRequest(CLIENT.spki));
  check("113. the same caPubs delivered on the waiting AND granting legs is deduped in the returned chain -> length 2 (leaf + one intermediate)", r113.outcome === "issued" && r113.chain.length === 2);

  var s114 = mk([H.ip(0, 0, certDer), H.pkiconf()], { intermediates: [pki.schema.x509.parse(H.caCert)] });   // an already-PARSED cert as an intermediate
  var r114 = await s114.session.enroll(H.irRequest(CLIENT.spki));
  check("114. a parsed-object caller intermediate is accepted (canonicalized via its tbsBytes, not re-parsed) -> issued", r114.outcome === "issued");

  var s115 = mk([H.pkiconf()]);
  check("115. a p10cr with an unparseable CSR -> the requested-key extraction fails closed, the build boundary rejects it", /^(cmp|crmf|csr)\//.test(await codeOf(s115.session.enroll({ p10cr: Buffer.from("not a csr at all") }))));

  var s116 = mk([H.ip(0, 0, certDer), H.pkiconf()]);
  var r116 = await s116.session.enroll({ ir: { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: Uint8Array.from(CLIENT.spki) } } });
  check("116. a certTemplate.publicKey supplied as a Uint8Array is normalized to a Buffer for the key match -> issued", r116.outcome === "issued");

  var ED = signing.makeSigner("ed25519", { cn: "ed-client" });
  var edLeaf117 = await H.makeCaSignedLeaf(pki, ED.spki, "ed-leaf");   // a CA-issued leaf carrying the Ed25519 key (no SPKI params)
  var s117 = mk([H.ip(0, 0, edLeaf117), H.pkiconf()]);
  var r117 = await s117.session.enroll(H.irRequest(ED.spki, null, ED.key));
  check("117. an Ed25519 request key (no SPKI parameters) key-matches an issued cert carrying it -> issued", r117.outcome === "issued");

  var s118 = mk([H.pkiconf()]);
  check("118. a p10cr whose arm is NOT a CSR Buffer/Uint8Array -> the requested-key extraction returns null, the build boundary rejects it", /^(cmp|crmf|csr)\//.test(await codeOf(s118.session.enroll({ p10cr: { not: "a csr buffer" } }))));

  var s119 = mk([H.ip(0, 0, certDer), H.pkiconf()]);   // the session best-effort normalizes an invalid string certReqId for matching, but the request itself fails closed at the crmf build boundary
  check("119. an unparseable string certReqId is normalized to the default for matching, then fails closed at the build boundary", /^(cmp|crmf|csr)\//.test(await codeOf(s119.session.enroll(H.irRequest(CLIENT.spki, "not-a-number")))));

  var s120 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-120" }, transport: H.fakeCa(pki, [H.ip(0, 0, await H.makePssExplicitUnknownHashCert(pki, CLIENT.spki)), H.pkiconf()], { macSecret: "s3cr3t-120" }).transport, sleep: function () { return Promise.resolve(); } });
  check("120. an RSASSA-PSS cert with an EXPLICIT but unmapped hashAlgorithm (SHA-1) -> cmp/bad-cert-response (the resolver reads the OID and refuses)", await codeOf(s120.enroll(H.irRequest(CLIENT.spki, null, CLIENT.key))) === "cmp/bad-cert-response");

  // ===== 121. the signer-path reserve is sized to the response's OWN extraCerts, not a static 32: a response
  //            carrying only its signer does NOT forfeit a needed caller intermediate below the ceiling =====
  var s121f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { deepSigner: true, deepSignerBareExtra: true });   // the deep signer chains via intCaCert, but its response carries ONLY the signer
  var callerPool121 = DISTINCT.slice(0, 903).concat([H.intCaCert]);   // exactly the 1000-candidate ceiling: 999 filler + the needed issuer LAST -- a response carrying only its signer must reserve ZERO (the signer is not appended), else this last slot is truncated
  var s121 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: callerPool121, transport: s121f.transport, sleep: function () { return Promise.resolve(); } });
  check("121. a response carrying only its signer reserves ZERO issuer slots (the signer is excluded from the append pool), so the 1000th caller intermediate (the needed issuer) is retained -> issued (counting the signer would reserve 1 and truncate it to cmp/untrusted-signer)", (await s121.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 122. the transcript retains at most TRANSCRIPT_RETAIN_RESPONSES * maxResponseBytes of payload: a
  //            padded-response polling flood is bounded (later legs keep metadata + byteLength, drop the payload) =====
  var PAD122 = 40;   // ~20 KiB of duplicate extraCerts per response (deduped away by verify; only inflates the wire size)
  var legs122 = [{ body: H.ip(0, 3), padExtraCerts: PAD122 }, { body: H.pollRep(0, 1), padExtraCerts: PAD122 }, { body: H.pollRep(0, 1), padExtraCerts: PAD122 }, { body: H.pollRep(0, 1), padExtraCerts: PAD122 }, { body: H.ip(0, 0, certDer), padExtraCerts: PAD122 }, { body: H.pkiconf(), padExtraCerts: PAD122 }];
  var s122 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: H.fakeCa(pki, legs122).transport, maxResponseBytes: 32768, sleep: function () { return Promise.resolve(); } });
  var r122 = await s122.enroll(H.irRequest(CLIENT.spki));
  var retained122 = r122.transcript.reduce(function (sum, e) { return sum + (Buffer.isBuffer(e.bytes) ? e.bytes.length : 0); }, 0);
  var truncated122 = r122.transcript.filter(function (e) { return e.truncated === true; });
  check("122a. a padded-response polling flood still issues (transcript truncation is diagnostic-only, never blocks the transaction)", r122.outcome === "issued");
  check("122b. the retained transcript payload stays within TRANSCRIPT_RETAIN_RESPONSES * maxResponseBytes (an unbounded transcript would retain every leg)", retained122 <= 32768 * 2);
  check("122c. the over-cap legs are truncated -- metadata + byteLength retained, payload dropped to bytes:null", truncated122.length > 0 && truncated122.every(function (e) { return e.bytes === null && typeof e.byteLength === "number" && e.byteLength > 0; }));

  // ===== 123. a 200 response whose body is NOT a parseable PKIMessage fails closed at the transfer parse gate
  //            (RFC 9811 sec. 3.3) -> a typed cmp error, and the transaction is not advanced =====
  var garbageTransport = function () { return Promise.resolve({ status: 200, headers: { "content-type": "application/pkixcmp" }, body: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x2a]) }); };
  var s123 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: garbageTransport, sleep: function () { return Promise.resolve(); } });
  check("123. a non-PKIMessage 200 response fails closed at the transfer parse gate -> a typed cmp error (the transaction is not advanced)", /^cmp\//.test(await codeOf(s123.enroll(H.irRequest(CLIENT.spki)))));

  // ===== 125. the same authenticated caPubs across a waiting leg and the grant accumulates ONCE (byte-identity
  //            dedup bounds the cross-leg pool) while the leaf still chains via the accumulated issuer =====
  var intLeaf125 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // needs intCaCert (delivered in caPubs) to chain to the anchor
  var legs125 = [{ body: H.ip(0, 3, null, { caPubs: [H.intCaCert] }) }, H.pollRep(0, 1), { body: H.ip(0, 0, intLeaf125, { caPubs: [H.intCaCert] }) }, H.pkiconf()];
  var s125 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: H.fakeCa(pki, legs125).transport, sleep: function () { return Promise.resolve(); } });
  check("125. the same authenticated caPubs delivered across a waiting leg and the grant is deduped (bounded accumulation) yet still chains the leaf -> issued", (await s125.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 126. caPubs is bounded by a BYTE budget with capacity RESERVED for the grant: a flood of waiting caPubs
  //            cannot starve the grant's own required issuer (byte budget + grant reserve) =====
  var intLeaf126 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // chains via intCaCert, delivered ONLY in the grant's caPubs
  var legs126 = [
    { body: H.ip(0, 3, null, { caPubs: DISTINCT.slice(0, 22) }) },   // waiting-leg caPubs floods (junk certs) filling the byte budget
    { body: H.ip(0, 3, null, { caPubs: DISTINCT.slice(22, 44) }) },
    { body: H.ip(0, 3, null, { caPubs: DISTINCT.slice(44, 66) }) },
    { body: H.ip(0, 3, null, { caPubs: DISTINCT.slice(66, 88) }) },
    { body: H.ip(0, 0, intLeaf126, { caPubs: [H.intCaCert] }) }, H.pkiconf(),   // the GRANT delivers the leaf's own required issuer
  ];
  var s126 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: H.fakeCa(pki, legs126).transport, maxResponseBytes: 8192, sleep: function () { return Promise.resolve(); } });
  check("126. a waiting-caPubs flood filling the byte budget does NOT drop the grant's own required issuer (reserved capacity) -> issued (without the grant reserve the delivered issuer is starved to cmp/untrusted-signer)", (await s126.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 127. a PREBORN-fallback first leg authenticates its OWN extraCerts (via opts.expectedSender), so the
  //            issuer is cached and a later extraCerts-less leg reuses it (a cached-signer fallback would not) =====
  var s127f = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), stripSignerExtra: true }, { body: H.pkiconf(), noExtraCerts: true }], { deepSigner: true });   // grant: signer via expectedSender, issuer in extraCerts; pkiConf: no extraCerts
  var s127 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s127f.transport, expectedSender: H.deepSignerCert, sleep: function () { return Promise.resolve(); } });
  check("127. a preborn-fallback first leg caches its authenticated issuer, so a later extraCerts-less leg reuses it -> issued (without caching the later leg retries with an empty chain and fails as cmp/untrusted-signer)", (await s127.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 128. an issued leaf whose issuer is delivered NOWHERE (no caPubs, not in extraCerts) cannot chain:
  //            path.build THROWS path/no-path, re-typed to cmp/bad-cert-response before confirmation (not leaked) =====
  var intLeaf128 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // issued by intCaCert, which no leg delivers
  check("128. an issued leaf whose issuer is delivered nowhere -> cmp/bad-cert-response (path.build's path/no-path is re-typed to the domain error, never leaked)", await codeOf(mk([H.ip(0, 0, intLeaf128), H.pkiconf()]).session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-cert-response");

  // ===== 129. a grant re-delivering an issuer that a WAITING leg also supplied (so eviction removed it from the
  //            front) re-adds it -- the dedup set tracks the RETAINED set, not history -> issued =====
  var intLeaf129 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // chains via intCaCert
  var legs129 = [
    { body: H.ip(0, 3, null, { caPubs: [H.intCaCert].concat(DISTINCT.slice(100, 120)) }) },   // intCaCert FIRST (oldest -> first evicted), then junk
    { body: H.ip(0, 3, null, { caPubs: DISTINCT.slice(120, 140) }) },
    { body: H.ip(0, 3, null, { caPubs: DISTINCT.slice(140, 160) }) },
    { body: H.ip(0, 0, intLeaf129, { caPubs: [DISTINCT[160], H.intCaCert] }) },   // grant: a NEW junk (evicts intCaCert from the front) then RE-delivers intCaCert
    H.pkiconf(),
  ];
  var s129 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: H.fakeCa(pki, legs129).transport, maxResponseBytes: 8192, sleep: function () { return Promise.resolve(); } });
  check("129. a grant re-delivering an issuer a waiting leg supplied (which eviction removed) re-adds it -> issued (a stale dedup set would drop the re-delivered issuer to cmp/bad-cert-response)", (await s129.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 130. a response whose extraCerts DUPLICATES a caller intermediate spends no extra pool slot on the
  //            duplicate, so the signer's real issuer (last in a ceiling-filling caller pool) survives -> issued =====
  var dupCert130 = DISTINCT[500];   // a caller cert the response ALSO delivers in its extraCerts
  var s130f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { deepSigner: true, deepSignerDupExtra: dupCert130 });   // response extraCerts = [deepSigner, dupCert130]; the needed intCaCert comes from the caller pool
  var callerPool130 = DISTINCT.slice(0, 903).concat([H.intCaCert]);   // 999 junk (INCLUDING dupCert130) + the needed issuer LAST, exactly at the ceiling
  var s130 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: callerPool130, transport: s130f.transport, sleep: function () { return Promise.resolve(); } });
  check("130. a response extraCert duplicating a caller intermediate spends no reserved slot, so the signer's real issuer (the 1000th caller cert) survives -> issued (counting the duplicate truncates it to cmp/untrusted-signer)", (await s130.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 131. a response whose signer is NOT the first extraCert (reordered -- cmp.verify resolves it by
  //            senderKID / signature match) + a ceiling-filling caller pool: the delivered issuer survives -> issued
  //            (blindly excluding extraCerts[0] as the signer would drop the real issuer) =====
  var s131f = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), reverseExtra: true, senderKid: H.deepSignerSki }, H.pkiconf()], { deepSigner: true });   // extraCerts = [intCaCert, deepSigner]; senderKID names deepSigner (SECOND) so the issuer intCaCert is FIRST
  var s131 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: DISTINCT, transport: s131f.transport, sleep: function () { return Promise.resolve(); } });   // 1000 junk caller certs at the ceiling
  check("131. a response whose signer is not the first extraCert + a ceiling-filling caller pool -> the delivered issuer survives -> issued (treating extraCerts[0] as the signer would drop the real issuer to cmp/untrusted-signer)", (await s131.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 132. leaf validation retries CALLER-first when the caPubs-first pool cannot build a path: a
  //            ceiling-filling caller pool with the required issuer LAST + an unrelated caPubs entry -> issued =====
  var intLeaf132 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // chains via intCaCert (in the caller pool, LAST)
  var caller132 = DISTINCT.slice(0, 903).concat([H.intCaCert]);   // 1000 caller certs at the ceiling, intCaCert last
  var s132f = H.fakeCa(pki, [H.ip(0, 0, intLeaf132, { caPubs: [DISTINCT[903]] }), H.pkiconf()]);   // an UNRELATED grant caPubs entry (not the leaf's issuer, not in the caller pool)
  var s132 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], intermediates: caller132, transport: s132f.transport, sleep: function () { return Promise.resolve(); } });
  check("132. a ceiling-filling caller pool with the required issuer last + an unrelated caPubs entry -> leaf validation retries caller-first -> issued (a caPubs-first-only pool truncates the required issuer to cmp/bad-cert-response)", (await s132.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 133. a grant re-delivering a RETAINED issuer BEFORE a new caPubs entry promotes it to newest, so the
  //            later new entry's eviction cannot drop it (its grant occurrence is otherwise skipped as a dup) =====
  var intLeaf133 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // chains via intCaCert
  var legs133 = [
    { body: H.ip(0, 3, null, { caPubs: [H.intCaCert].concat(DISTINCT.slice(200, 220)) }) },   // intCaCert FIRST (oldest retained), then junk
    { body: H.ip(0, 3, null, { caPubs: DISTINCT.slice(220, 240) }) },
    { body: H.ip(0, 3, null, { caPubs: DISTINCT.slice(240, 260) }) },
    { body: H.ip(0, 0, intLeaf133, { caPubs: [H.intCaCert, DISTINCT[260]] }) },   // grant: intCaCert (DUP, first -> promoted) then a NEW junk (would evict the oldest)
    H.pkiconf(),
  ];
  var s133 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: H.fakeCa(pki, legs133).transport, maxResponseBytes: 8192, sleep: function () { return Promise.resolve(); } });
  check("133. a grant re-delivering a retained issuer before a new entry promotes it, so eviction cannot drop it -> issued (leaving it at its old position lets the new entry evict it, failing path validation)", (await s133.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 134. a grant with MORE than CAPUBS_MAX distinct caPubs and the required issuer FIRST keeps the earliest
  //            grant entries (a later grant entry never evicts an earlier one) -> issued =====
  var intLeaf134 = await H.makeIntSignedLeaf(pki, CLIENT.spki);   // chains via intCaCert
  var s134f = H.fakeCa(pki, [H.ip(0, 0, intLeaf134, { caPubs: [H.intCaCert].concat(DISTINCT.slice(0, 70)) }), H.pkiconf()]);   // intCaCert FIRST, then 70 junk (> CAPUBS_MAX=64)
  var s134 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s134f.transport, sleep: function () { return Promise.resolve(); } });
  check("134. a grant with more than CAPUBS_MAX caPubs keeps the EARLIEST (a later grant entry never evicts an earlier one), so the required issuer delivered first survives -> issued (evicting grant entries drops it to cmp/bad-cert-response)", (await s134.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 135. a purely-LOCAL transfer config error (an unparseable url) does NOT consume the one-shot session --
  //            it is rejected before the transport, so the caller can fix the config and retry =====
  var s135 = pki.cmp.session({ url: "http://[bad", key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()]).transport, sleep: function () { return Promise.resolve(); } });
  var c135a = await codeOf(s135.enroll(H.irRequest(CLIENT.spki)));   // first attempt: local URL error
  var c135b = await codeOf(s135.enroll(H.irRequest(CLIENT.spki)));   // retry: still the config error, NOT a consumed-session error
  check("135. a local config error (bad url) fails before the transport and does NOT consume the session -> the retry sees the same config error, not a consumed-session error", c135a === "cmp/bad-url" && c135b === "cmp/bad-url");

  // ===== 136. a same-identity signer ROTATION whose issuer was delivered on an EARLIER leg: the rotated signer's
  //            bare extraCerts resolve it, and the CACHED chain (folded into the PRIMARY signer pool) supplies its
  //            intermediate -> issued. Without the cached chain in the primary, the rotation is rejected: the
  //            fallback forces the earlier signer's key and cannot verify the rotated signature. =====
  var s136f = H.fakeCa(pki, [H.ip(0, 3), { body: H.ip(0, 0, certDer), rotateDeepSigner: true }, H.pkiconf()], { deepSigner: true });   // waiting leg caches [deepSigner, intermediate]; the grant rotates to a same-subject deep signer carrying ONLY itself
  var s136 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s136f.transport, sleep: function () { return Promise.resolve(); } });
  check("136. a same-identity signer rotation whose issuer was delivered on an earlier leg -> issued (the cached chain in the PRIMARY signer pool supplies the rotated signer's intermediate; without it the fallback forces the earlier key and fails as cmp/protection-failed)", (await s136.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 137. a non-function opts.transport -> cmp/bad-input at CONSTRUCTION -- it would otherwise pass cmp.transfer's
  //            local url/budget checks and throw a raw TypeError when invoked, a local error the send path would mark
  //            as consuming the one-shot session. =====
  check("137. a non-function opts.transport -> cmp/bad-input at construction (a config typo cannot pass the local transfer checks and then throw a session-consuming TypeError when the transport is invoked)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: 123 }); })) === "cmp/bad-input");

  // ===== 138. a POST-ENGAGE transfer error DOES consume the one-shot session: a 200 response with a non-CMP
  //            content-type (cmp.transfer's cmp/bad-content-type, thrown AFTER the transport returned) means a
  //            request reached the transport, so the retry is refused as already-completed -- the complement of
  //            135's LOCAL config error, which leaves the session retryable. =====
  var s138f = H.fakeCa(pki, [{ body: H.ip(0, 0, certDer), contentType: "text/plain" }, H.pkiconf()]);
  var s138 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s138f.transport, sleep: function () { return Promise.resolve(); } });
  var c138a = await codeOf(s138.enroll(H.irRequest(CLIENT.spki)));   // a request reached the transport, THEN the content-type check failed
  var c138b = await codeOf(s138.enroll(H.irRequest(CLIENT.spki)));   // the retry is refused -- the one-shot session was consumed
  check("138. a post-engage transfer error (bad content-type, after the transport returned) consumes the one-shot session -> the retry is refused as already-completed (unlike 135's local error, which leaves it retryable)", c138a === "cmp/bad-content-type" && c138b === "cmp/bad-input");

  // ===== 139. a same-identity signer rotation across TWO bare legs: the session caches the VALIDATED chain (the
  //            signer + the issuer path.build used), so the rotated signer's issuer -- delivered only on the FIRST
  //            (waiting) leg -- survives, and a SECOND bare leg from the rotated signer still chains -> issued.
  //            Caching the bare rotation leg's own extraCerts would discard the issuer, failing it as untrusted. =====
  var s139f = H.fakeCa(pki, [H.ip(0, 3), { body: H.ip(0, 0, certDer), rotateDeepSigner: true }, { body: H.pkiconf(), rotateDeepSigner: true }], { deepSigner: true });   // A(waiting,[A,int]) -> B(grant,[B]) -> B(pkiConf,[B]); B's issuer came only with A
  var s139 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s139f.transport, sleep: function () { return Promise.resolve(); } });
  check("139. a same-identity rotation across two bare legs caches the validated chain, so the establishing issuer survives -> issued (caching the bare rotation leg's own extraCerts would drop the issuer, failing the second bare leg as cmp/untrusted-signer)", (await s139.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 140. an on-path party pads the rotation leg's UNSIGNED extraCerts with the real signer + 31 unrelated
  //            parseable certificates. Because the session caches the VALIDATED chain (only certs on the trusted
  //            path), the padding is excluded and the establishing issuer survives, so the following bare leg still
  //            chains -> issued. Caching the raw (padded) extraCerts would evict the issuer -> cmp/untrusted-signer. =====
  var s140f = H.fakeCa(pki, [H.ip(0, 3), { body: H.ip(0, 0, certDer), rotateDeepSigner: true, padDistinctExtra: DISTINCT.slice(0, 31) }, { body: H.pkiconf(), rotateDeepSigner: true }], { deepSigner: true });   // the grant leg's extraCerts = [B] + 31 distinct junk (filling MAX_EXTRA_CERTS)
  var s140 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], transport: s140f.transport, sleep: function () { return Promise.resolve(); } });
  check("140. padding the rotation leg's unsigned extraCerts with 31 unrelated certs does not evict the establishing issuer, because the session caches the validated chain not the raw extraCerts -> issued (caching the padded extraCerts drops the issuer to cmp/untrusted-signer)", (await s140.enroll(H.irRequest(CLIENT.spki))).outcome === "issued");

  // ===== 141. a PARTIAL parsed expectedSender ({ tbsBytes } only) is rejected at CONSTRUCTION with the same
  //            full parsed-certificate check the path engine applies -- it would otherwise pass the tbsBytes-only
  //            detection and later throw a raw TypeError in senderBoundToCert, consuming the one-shot session. =====
  check("141. a partial parsed opts.expectedSender (a { tbsBytes } object, not a complete parsed certificate) -> cmp/bad-input at construction (a config error cannot pass the parsed-form detection and then throw a session-consuming TypeError mid-transaction)", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], expectedSender: { tbsBytes: Buffer.alloc(0) } }); })) === "cmp/bad-input");

  // ===== 142. a FROZEN options object with an empty MAC trustAnchors list: the session normalizes on a shallow
  //            copy, never the caller's frozen object, so construction does not throw a raw TypeError and the empty
  //            list is treated as absent -> issued (mutating the frozen opts would throw; the caller's object is
  //            also left unmodified for reuse across sessions). =====
  var s142f = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { macSecret: "s3cr3t-142" });
  var frozen142 = Object.freeze({ url: URL, mac: { secret: "s3cr3t-142" }, trustAnchors: [], transport: s142f.transport, sleep: function () { return Promise.resolve(); } });
  var r142 = await pki.cmp.session(frozen142).enroll(H.irRequest(CLIENT.spki, null, CLIENT.key));
  check("142. a frozen options object with an empty MAC trustAnchors list normalizes on a copy (not the caller's frozen object) -> issued (mutating the frozen opts would throw a raw TypeError at construction)", r142.outcome === "issued" && Array.isArray(frozen142.trustAnchors) && frozen142.trustAnchors.length === 0);

  // ===== 143. a custom transport that is INVOKED and then rejects with a coded error (cmp/bad-input -- a code the
  //            preflight also uses) DOES consume the one-shot session: engagement is detected by the transport
  //            being called, not by the error code. The retry is refused WITHOUT calling the transport again, so a
  //            request that may have reached the CA is never replayed under the same transactionID/nonce. =====
  var calls143 = 0;
  var s143 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], sleep: function () { return Promise.resolve(); },
    transport: function () { calls143 += 1; return Promise.reject(Object.assign(new Error("reached the CA, then failed"), { code: "cmp/bad-input", isCmpError: true })); } });
  var c143a = await codeOf(s143.enroll(H.irRequest(CLIENT.spki)));   // the transport is called (calls=1), then rejects with a preflight-shaped code
  var c143b = await codeOf(s143.enroll(H.irRequest(CLIENT.spki)));   // the retry is refused: the session was consumed, the transport is NOT called again
  check("143. a custom transport that is invoked then rejects with a coded error consumes the one-shot session -> the retry is refused without re-calling the transport (calls stays 1) (inferring pre-send from the code would let a delivered request replay under the same transactionID)", c143a === "cmp/bad-input" && c143b === "cmp/bad-input" && calls143 === 1);

  // ===== 144. a DEFAULT-transport session (no opts.transport): cmp.transfer's OWN preflight fails on a bad url
  //            BEFORE any transport call, and the default transport never reuses the preflight codes for its own
  //            network errors, so the code-based classification (used only for the default transport) correctly
  //            leaves the one-shot session retryable. =====
  var s144 = pki.cmp.session({ url: "http://[bad", key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], sleep: function () { return Promise.resolve(); } });   // NO opts.transport -> the default HTTP transport
  var c144a = await codeOf(s144.enroll(H.irRequest(CLIENT.spki)));   // cmp.transfer's url preflight throws cmp/bad-url before any transport call
  var c144b = await codeOf(s144.enroll(H.irRequest(CLIENT.spki)));   // the retry sees the same preflight error, not a consumed session
  check("144. a default-transport session with a bad url fails at cmp.transfer's preflight (before any transport call) and does not consume the session -> retryable (the default transport's own errors never reuse the preflight codes)", c144a === "cmp/bad-url" && c144b === "cmp/bad-url");

  // ===== 145. a default-transport session with NO TLS trust anchors: cmp.transfer refuses the unpinned server at
  //            preflight (cmp/no-trust-anchors) before any request -> the session stays retryable. =====
  var s145 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], sleep: function () { return Promise.resolve(); } });   // default transport, no opts.tls anchors
  var c145a = await codeOf(s145.enroll(H.irRequest(CLIENT.spki)));
  var c145b = await codeOf(s145.enroll(H.irRequest(CLIENT.spki)));
  check("145. a default-transport session without TLS trust anchors fails at preflight (cmp/no-trust-anchors, before any request) and does not consume the session -> retryable", c145a === "cmp/no-trust-anchors" && c145b === "cmp/no-trust-anchors");

  // ===== 146. a default-transport session with a bad transfer budget (an out-of-range timeout): cmp.transfer
  //            rejects it (cmp/bad-input) at preflight, after the TLS-anchor check, before any request -> retryable. =====
  var s146 = pki.cmp.session({ url: URL, key: CLIENT.key, cert: CLIENT.cert, trustAnchors: [H.caCert], tls: { anchors: [H.caCert] }, timeout: -5, sleep: function () { return Promise.resolve(); } });   // default transport, TLS pinned, bad timeout
  var c146a = await codeOf(s146.enroll(H.irRequest(CLIENT.spki)));
  var c146b = await codeOf(s146.enroll(H.irRequest(CLIENT.spki)));
  check("146. a default-transport session with an out-of-range transfer timeout fails at preflight (cmp/bad-input, before any request) and does not consume the session -> retryable", c146a === "cmp/bad-input" && c146b === "cmp/bad-input");

  // ===== 147/148. the intermediates cap is PER PROTECTION FLAVOR. A MAC session authenticates the response by the
  //                shared secret and never adds a signer chain, so it reserves only the caPubs slots (leaf
  //                validation) -- accepting 32 MORE distinct intermediates than a signature session (whose 904 cap
  //                rejects 905, vector 104). Its cap is PATH_BUILD_MAX_CANDIDATES - CAPUBS_MAX = 936. =====
  var DISTINCT_MAC = DISTINCT.concat(await H.manyDistinctCerts(pki, 33));   // 937 distinct (the extra 33 carry a different key, so distinct from DISTINCT's first 33)
  var macTransport147 = H.fakeCa(pki, [H.ip(0, 0, certDer), H.pkiconf()], { macSecret: "s3cr3t-147" }).transport;
  check("147. a MAC session accepts 936 distinct intermediates (only caPubs reserved, no signer chain) -> constructs (a signature session's 904 cap rejects far fewer)", typeof pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-147" }, trustAnchors: [H.caCert], intermediates: DISTINCT_MAC.slice(0, 936), transport: macTransport147, sleep: function () { return Promise.resolve(); } }).enroll === "function");
  check("148. a MAC session rejects 937 distinct intermediates (one over its per-flavor cap) -> cmp/bad-input at construction", await codeOf(Promise.resolve().then(function () { return pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-148" }, trustAnchors: [H.caCert], intermediates: DISTINCT_MAC.slice(0, 937) }); })) === "cmp/bad-input");

  // ============================================================================================
  // Revocation (rr -> rp, RFC 9483 sec. 4.2) and the support messages (genm -> genp, sec. 4.3),
  // both under the same one-transaction shell as enroll. Delayed delivery for these operations
  // rides an ERROR body carrying status waiting (sec. 4.4), never an rp or a genp.
  // ============================================================================================

  var OWN = pki.schema.x509.parse(CLIENT.cert);             // the session's own protection certificate
  var OTHER = pki.schema.x509.parse(H.leafCert);            // a certificate this session did not protect with
  // A REAL CertificateList. A revocation response and a crlUpdate answer both deliver CRLs to a
  // caller that acts on them, so the fixture has to be the structure the operation claims: a
  // certificate would pass a shape-only reader and hand back something no revocation check reads.
  var REAL_CRL = await pki.crl.sign({
    thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: new Date("2026-02-01T00:00:00Z"),
    crlNumber: 1n, revoked: [{ serialNumber: 42n, revocationDate: new Date("2026-01-02T00:00:00Z") }],
  }, { key: CLIENT.key, cert: CLIENT.cert });
  // Decode the crlEntryDetails reasonCode out of a sent rr, so the encoding claims are byte claims.
  function sentRr(transport, i) { return pki.schema.cmp.parse(transport.calls[i].body).body.decoded; }
  function reasonOf(revDetails) {
    var exts = revDetails.crlEntryDetails;
    if (!Array.isArray(exts)) return "NO-CRL-ENTRY-DETAILS";
    for (var i = 0; i < exts.length; i++) {
      if (exts[i].name === "reasonCode") return Number(pki.asn1.read.enumerated(pki.asn1.decode(exts[i].value)));
    }
    return "NO-REASON-CODE";
  }

  // ===== 149. the happy path: rr -> rp(accepted) -> outcome:revoked =====
  var s149 = mk([H.rp(0)]);
  var r149 = await s149.session.revoke({ certificate: CLIENT.cert });
  check("149a. an accepted rp -> outcome:revoked", r149.outcome === "revoked");
  check("149b. the CA's PKIStatusInfo is surfaced on the verdict", r149.status && r149.status.status.code === 0);
  check("149c. exactly ONE request leg crossed the seam (the rr; a revocation has no confirmation handshake)", s149.transport.calls.length === 1);
  check("149d. the verdict carries the transactionID + a transcript of both directions", Buffer.isBuffer(r149.transactionID) && r149.transcript.length === 2);

  // ===== 150. the rr encoding: ONE RevDetails, issuer+serial of the named certificate, and a
  //            crlEntryDetails reasonCode that is PRESENT at 0 (sec. 4.2 requires it; RFC 5280
  //            sec. 5.3.1 omits unspecified(0) from a CRL entry, which is the opposite rule). =====
  var rr150 = sentRr(s149.transport, 0);
  check("150a. the rr carries exactly one RevDetails (sec. 4.2)", Array.isArray(rr150) && rr150.length === 1);
  check("150b. certDetails names the certificate by serialNumber", rr150[0].certDetails.serialNumber === OWN.serialNumber);
  check("150c. certDetails names the certificate by issuer", rr150[0].certDetails.issuer != null);
  check("150d. crlEntryDetails carries a reasonCode of 0 when no reason was given -- PRESENT, not omitted (sec. 4.2)", reasonOf(rr150[0]) === 0);

  // ===== 151. a named reason encodes as its CRLReason value =====
  var s151 = mk([H.rp(0)]);
  await s151.session.revoke({ certificate: CLIENT.cert, reason: "keyCompromise" });
  check("151a. reason:keyCompromise encodes as CRLReason 1", reasonOf(sentRr(s151.transport, 0)[0]) === 1);
  var s151b = mk([H.rp(0)]);
  await s151b.session.revoke({ certificate: CLIENT.cert, reason: "cessationOfOperation" });
  check("151b. reason:cessationOfOperation encodes as CRLReason 5", reasonOf(sentRr(s151b.transport, 0)[0]) === 5);
  check("151c. an unknown reason name -> cmp/bad-input", await codeOf(mk([H.rp(0)]).session.revoke({ certificate: CLIENT.cert, reason: "notARealReason" })) === "cmp/bad-input");
  // A caller field can be an accessor, so a field read twice is two values: the one the checks saw
  // and the one the message carries. The request is reduced at the door, so what goes on the wire
  // is what was checked.
  var flip151 = 0, moving151 = { certificate: CLIENT.cert };
  Object.defineProperty(moving151, "reason", { enumerable: true, get: function () { flip151 += 1; return flip151 === 1 ? "keyCompromise" : "cessationOfOperation"; } });
  var s151d = mk([H.rp(0)]);
  await s151d.session.revoke(moving151);
  check("151d. a reason accessor cannot put a different CRLReason on the wire than the one checked", reasonOf(sentRr(s151d.transport, 0)[0]) === 1);

  // An rp MAY deliver CRLs alongside the status, and they reach the caller on the same verdict, so
  // the rule that a support-message value must be the structure it claims holds here too.
  var s149c = mk([H.rp(0, null, { crls: [REAL_CRL] })]);
  var r149c = await s149c.session.revoke({ certificate: CLIENT.cert });
  check("149e. an rp's delivered CRLs are surfaced on the verdict", r149c.outcome === "revoked" && r149c.crls.length === 1 && r149c.crls[0].equals(REAL_CRL));
  // sec. 4.2: an rp MAY name the certificates it revoked in revCerts. This session revokes exactly its
  // own certificate, so a verified verdict must not report an UNRELATED certificate as revoked: revCerts
  // is bound to the certificate the request named -- exactly one entry, its issuer + serialNumber equal.
  var clientRevId = { issuer: { directoryName: [{ commonName: "client" }] }, serialNumber: pki.schema.x509.parse(CLIENT.cert).serialNumber };
  check("149f. an rp whose revCerts names a DIFFERENT issuer/serial -> refused (an unrelated cert must not read as revoked)", /^cmp\//.test(await codeOf(mk([H.rp(0, null, { revCerts: [{ issuer: { directoryName: [{ commonName: "some-other-ca" }] }, serialNumber: 999n }] })]).session.revoke({ certificate: CLIENT.cert }))));
  check("149g. an rp carrying MORE than one revCerts entry -> refused (this session revokes exactly one)", /^cmp\//.test(await codeOf(mk([H.rp(0, null, { revCerts: [clientRevId, clientRevId] })]).session.revoke({ certificate: CLIENT.cert }))));
  var r149h = await mk([H.rp(0, null, { revCerts: [clientRevId] })]).session.revoke({ certificate: CLIENT.cert });
  check("149h. an rp whose single revCerts names THIS certificate -> revoked, surfaced", r149h.outcome === "revoked" && Array.isArray(r149h.revokedCerts) && r149h.revokedCerts.length === 1);
  // The verdict holds those entries to being CertificateLists through the same reader the
  // support-message answer uses, which vector 172a2 drives. There is no vector for it HERE
  // because this fake responder builds its messages with pki.cmp.build, and that verb already
  // refuses a non-CRL in rp.crls (probed: cmp/bad-rev-rep, "a crls entry is not a valid CRL").
  // Reaching it needs a peer that does not build through this toolkit, so the check on this path
  // is a defense against exactly that and is deliberately left without a vector of its own.

  // ===== 152. a rejection is a terminal VERDICT carrying the diagnostic, never a throw =====
  var r152 = await mk([H.rp(2, ["badRequest"])]).session.revoke({ certificate: CLIENT.cert });
  check("152. a rejection rp -> outcome:rejected with the failInfo surfaced", r152.outcome === "rejected" && r152.status.status.code === 2 && r152.status.failInfo.bits.indexOf("badRequest") !== -1);

  // sec. 4.2 makes failInfo PROHIBITED under an accepted status, so a response asserting both at once
  // is contradictory: it says the revocation succeeded and names the reason it did not.
  check("152b. an ACCEPTED rp carrying failInfo -> refused (sec. 4.2: failInfo MUST be absent)", /^cmp\//.test(await codeOf(mk([H.rp(0, ["badRequest"])]).session.revoke({ certificate: CLIENT.cert }))));

  // ===== 153. sec. 4.2: "MUST contain a sequence of one element" -- two statuses is refused =====
  check("153. an rp carrying more than one status -> refused (sec. 4.2)", /^cmp\//.test(await codeOf(mk([H.rpMultiStatus()]).session.revoke({ certificate: CLIENT.cert }))));

  // ===== 154. sec. 4.2: the rr is signed WITH the certificate being revoked, which is how the
  //            authorization to revoke is proven. Revoking any other certificate is refused. =====
  check("154. revoking a certificate the session did not protect with -> cmp/bad-input (sec. 4.2)", await codeOf(mk([H.rp(0)]).session.revoke({ certificate: H.leafCert })) === "cmp/bad-input");
  check("154b. the same via an explicit certDetails naming another certificate -> cmp/bad-input", await codeOf(mk([H.rp(0)]).session.revoke({ certDetails: { issuer: OTHER.issuer.bytes, serialNumber: OTHER.serialNumber } })) === "cmp/bad-input");

  // ===== 155. a MAC session has no certificate, so it cannot prove authorization to revoke one =====
  var mac155 = H.fakeCa(pki, [H.rp(0)], { macSecret: "s3cr3t-155" });
  var s155 = pki.cmp.session({ url: URL, mac: { secret: "s3cr3t-155" }, transport: mac155.transport });
  check("155. a PBMAC1 session refuses revoke -> cmp/bad-input (sec. 4.2 requires signature protection with the revoked certificate)", await codeOf(s155.revoke({ certificate: CLIENT.cert })) === "cmp/bad-input");
  // The comparison needs opts.cert to BE a certificate. A session constructed with something else
  // fails here rather than at the first build, so the transaction is never engaged.
  var s155b = pki.cmp.session({ url: URL, key: CLIENT.key, cert: Buffer.from([1, 2, 3]), trustAnchors: [H.caCert], transport: mk([H.rp(0)]).transport });
  check("155b. a session whose opts.cert is not a certificate refuses revoke -> cmp/bad-input", await codeOf(s155b.revoke({ certificate: CLIENT.cert })) === "cmp/bad-input");

  // ===== 156/157. the response arm and the verify-before-read ordering =====
  check("156. an rr answered by an ip -> cmp/unexpected-arm", await codeOf(mk([H.ip(0, 0, certDer)]).session.revoke({ certificate: CLIENT.cert })) === "cmp/unexpected-arm");
  check("157. a TAMPERED rp carrying an ACCEPTED status is refused BEFORE the status is read", await codeOf(mk([{ body: H.rp(0), tamper: true }]).session.revoke({ certificate: CLIENT.cert })) === "cmp/protection-failed");

  // ===== 158/159. delayed delivery (sec. 4.4): an ERROR body with status waiting drives the poll
  //                loop, and the pollReq refers to the whole message with certReqId -1. =====
  var s158 = mk([H.errorWaiting(), H.pollRep(-1, 1), H.pollRep(-1, 1), H.pollRep(-1, 1)], { maxPolls: 2 });
  var r158 = await s158.session.revoke({ certificate: CLIENT.cert });
  check("158a. an error body with status waiting drives the poll loop -> poll-timeout at the budget", r158.outcome === "poll-timeout" && r158.polls === 2);
  check("158b. the pollReq refers to the whole message with certReqId -1 (sec. 4.4)", sentRr(s158.transport, 1)[0].certReqId === -1n);
  var s159 = mk([H.errorWaiting(), H.pollRep(-1, 1), H.rp(0)]);
  var r159 = await s159.session.revoke({ certificate: CLIENT.cert });
  check("159. polling through to the final rp -> revoked", r159.outcome === "revoked" && r159.polls === 2);
  // sec. 4.2/4.4: an error message answering a revoke/info is a rejection (status rejection(2)) or, for
  // delayed delivery, waiting(3) with no failInfo. accepted(0), grantedWithMods(1), or a status in 4..6 is
  // malformed for an error and is refused, not surfaced as a trusted "rejected" verdict whose PKIStatusInfo
  // contradicts it -- the same call the rp classifier makes for an unsupported status. A waiting error
  // carrying failInfo is likewise refused (a wait is not a failure). status-2 rejection and status-3
  // waiting-without-failInfo (tests 152/158a/159) keep their meaning.
  check("159b. an error status accepted(0) answering a revoke -> refused, not a rejected verdict", await codeOf(mk([H.errorBody(0)]).session.revoke({ certificate: CLIENT.cert })) === "cmp/bad-error");
  check("159c. an error status grantedWithMods(1) -> refused", await codeOf(mk([H.errorBody(1)]).session.revoke({ certificate: CLIENT.cert })) === "cmp/bad-error");
  check("159d. an error status revocationNotification(5) -> refused", await codeOf(mk([H.errorBody(5)]).session.revoke({ certificate: CLIENT.cert })) === "cmp/bad-error");
  check("159e. a waiting(3) error carrying failInfo -> refused (sec. 4.4 forbids failInfo on waiting)", await codeOf(mk([H.errorBody(3, ["badRequest"])]).session.revoke({ certificate: CLIENT.cert })) === "cmp/bad-error");

  // ===== 160/161/162. one transaction per session, and the request-shape doors =====
  var s160 = mk([H.rp(0), H.rp(0)]);
  await s160.session.revoke({ certificate: CLIENT.cert });
  check("160a. a SECOND revoke on a consumed session -> cmp/bad-input", await codeOf(s160.session.revoke({ certificate: CLIENT.cert })) === "cmp/bad-input");
  check("160b. an enroll on a session already consumed by a revoke -> cmp/bad-input", await codeOf(s160.session.enroll(H.irRequest(CLIENT.spki))) === "cmp/bad-input");
  check("161. an unknown revoke request key -> cmp/bad-input", await codeOf(mk([H.rp(0)]).session.revoke({ certificate: CLIENT.cert, bogus: 1 })) === "cmp/bad-input");
  check("162a. a revoke naming neither certificate nor certDetails -> cmp/bad-input", await codeOf(mk([H.rp(0)]).session.revoke({})) === "cmp/bad-input");
  check("162b. a revoke naming BOTH certificate and certDetails -> cmp/bad-input", await codeOf(mk([H.rp(0)]).session.revoke({ certificate: CLIENT.cert, certDetails: { issuer: OWN.issuer.bytes, serialNumber: OWN.serialNumber } })) === "cmp/bad-input");
  check("162c. a non-object revoke request -> cmp/bad-input", await codeOf(mk([H.rp(0)]).session.revoke(7)) === "cmp/bad-input");
  check("162d. a revoke request.certificate that is not a certificate -> cmp/bad-input", await codeOf(mk([H.rp(0)]).session.revoke({ certificate: Buffer.from([1, 2, 3]) })) === "cmp/bad-input");
  // A number is neither a name string, an RDN array, nor raw Name DER, so the CertTemplate builder
  // refuses it and the session translates that into its own code rather than leaking a crmf/ one.
  check("162e. a certDetails whose issuer is not a name -> cmp/bad-rev-req", await codeOf(mk([H.rp(0)]).session.revoke({ certDetails: { issuer: 12345, serialNumber: 1n } })) === "cmp/bad-rev-req");
  check("162f. a certDetails omitting serialNumber -> refused before the transport engages", /^cmp\//.test(await codeOf(mk([H.rp(0)]).session.revoke({ certDetails: { issuer: OWN.issuer.bytes } }))));

  // ===== 162g. KEM ciphertext (sec. 5.3.19.18): the support message a client whose key can only
  //             establish secrets asks for, so it can protect its own messages with that key. =====
  var kemCtValue = B.sequence([B.sequence([B.oid(pki.oid.byName("id-ml-kem-768"))]),
    B.octetString(Buffer.alloc(1088, 0x2a))]);
  var s162g = mk([H.genpOf("kemCiphertextInfo", kemCtValue)]);
  var r162g = await s162g.session.info({ kemCiphertext: true });
  check("162g. info({kemCiphertext}) answers with the algorithm and the ciphertext",
    r162g.outcome === "answered" && r162g.operation === "kemCiphertext" && r162g.present === true &&
    r162g.value.kem.name === "id-ml-kem-768" && r162g.value.ct.length === 1088);
  var genm162g = sentRr(s162g.transport, 0);
  check("162h. the genm asks under id-it-KemCiphertextInfo and carries no value",
    Array.isArray(genm162g) && genm162g.length === 1 && genm162g[0].name === "kemCiphertextInfo");
  var r162i = await mk([H.genpOf("kemCiphertextInfo", null)]).session.info({ kemCiphertext: true });
  check("162i. an answer carrying no ciphertext is the absence, not a value",
    r162i.outcome === "answered" && r162i.present === false);
  // A ciphertext is only an answer if this client can decapsulate it and there is something to open.
  check("162j. a KEM this client cannot decapsulate under is refused",
    (await codeOf(mk([H.genpOf("kemCiphertextInfo", B.sequence([
      B.sequence([B.oid(pki.oid.byName("id-ml-dsa-65"))]), B.octetString(Buffer.alloc(64, 1))]))])
      .session.info({ kemCiphertext: true }))) === "cmp/bad-info-value");
  check("162k. an empty ciphertext is refused",
    (await codeOf(mk([H.genpOf("kemCiphertextInfo", B.sequence([
      B.sequence([B.oid(pki.oid.byName("id-ml-kem-768"))]), B.octetString(Buffer.alloc(0))]))])
      .session.info({ kemCiphertext: true }))) === "cmp/bad-info-value");
  // An ML-KEM ciphertext is a fixed size, so a length the named algorithm never produces could not be
  // decapsulated and is refused rather than surfaced as usable material.
  check("162l. a ciphertext of the wrong length for the named algorithm is refused",
    (await codeOf(mk([H.genpOf("kemCiphertextInfo", B.sequence([
      B.sequence([B.oid(pki.oid.byName("id-ml-kem-768"))]), B.octetString(Buffer.alloc(768, 1))]))])
      .session.info({ kemCiphertext: true }))) === "cmp/bad-info-value");
  check("162m. the length each parameter set does produce is accepted",
    (await mk([H.genpOf("kemCiphertextInfo", B.sequence([
      B.sequence([B.oid(pki.oid.byName("id-ml-kem-512"))]), B.octetString(Buffer.alloc(768, 1))]))])
      .session.info({ kemCiphertext: true })).value.ct.length === 768);

  // ===== 163/164. caCerts (sec. 4.3.1): the request infoValue MUST be absent; the response
  //                carries a sequence of certificates, or nothing when none are available. =====
  var caCertsValue = B.sequence([B.raw(H.caCert), B.raw(H.intCaCert)]);
  var s163 = mk([H.genpOf("caCerts", caCertsValue)]);
  var r163 = await s163.session.info({ caCerts: true });
  check("163a. info({caCerts}) -> outcome:answered naming the operation", r163.outcome === "answered" && r163.operation === "caCerts");
  check("163b. the response certificates are surfaced", Array.isArray(r163.value) && r163.value.length === 2 && r163.value[0].equals(H.caCert));
  var genm163 = sentRr(s163.transport, 0);
  check("163c. the genm carries exactly one InfoTypeAndValue with the caCerts infoType", Array.isArray(genm163) && genm163.length === 1 && genm163[0].name === "caCerts");
  check("163d. the request infoValue is ABSENT (sec. 4.3.1)", genm163[0].value === null);
  // A support-message answer is a value the operator ACTS on -- a chain is built from these, a
  // revocation decision is read out of that CRL -- so each entry has to be the structure the
  // operation names. The CMP schema reads the slot as a raw SEQUENCE by design, which leaves this
  // to the verb that hands the bytes back.
  var notACert = B.sequence([B.sequence([B.integer(1n)])]);   // well-formed DER, not a Certificate
  check("163e. a caCerts entry that is not an X.509 certificate -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("caCerts", B.sequence([B.raw(notACert)]))]).session.info({ caCerts: true }))));
  // sec. 4.3.1 returns CA certificates for chain construction, so an entry that parses but is an
  // END-ENTITY certificate (basicConstraints cA FALSE) is refused -- surfacing it hands the caller a
  // list nothing can chain through. The same CA-capability rule the rootCaKeyUpdate certs are held to.
  var eeSigner = signing.makeSigner("ec-p256", { cn: "leaf-not-a-ca" });
  var EE_NOT_CA = await pki.x509.sign({ subject: "leaf-not-a-ca", subjectPublicKey: eeSigner.spki,
    notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: false }, keyUsage: ["digitalSignature"] } },
    { key: eeSigner.key, name: "leaf-not-a-ca", publicKey: eeSigner.spki });
  check("163f. a caCerts entry that parses but is an END-ENTITY certificate -> refused (sec. 4.3.1 returns CA certificates)", /^cmp\//.test(await codeOf(mk([H.genpOf("caCerts", B.sequence([B.raw(H.caCert), B.raw(EE_NOT_CA)]))]).session.info({ caCerts: true }))));
  var r164 = await mk([H.genpOf("caCerts")]).session.info({ caCerts: true });
  check("164. a caCerts response with no infoValue -> answered with present:false and a null value (sec. 4.3.1)", r164.outcome === "answered" && r164.present === false && r164.value === null);

  // ===== 165/166/167. rootCaCert -> rootCaKeyUpdate (sec. 4.3.2): the two OIDs DIFFER across the
  //                    exchange, and the profile makes newWithOld required where RFC 9480's ASN.1
  //                    marks it OPTIONAL. =====
  // A root CA key update is three certificates in NAMED relationships (sec. 4.3.2), so the fixture
  // has to be a real rollover: OLD is the root the request names, NEW is the replacement, and the
  // two cross-certificates each carry one key signed by the other. Three unrelated certificates
  // would establish nothing, which is the whole reason the relationships are checked.
  var OLDK = signing.makeSigner("ec-p256", { cn: "root-old" });
  var NEWK = signing.makeSigner("ec-p256", { cn: "root-new" });
  var VALID = { notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z"),
    extensions: { basicConstraints: { cA: true }, keyUsage: ["keyCertSign", "cRLSign"] } };
  var OLD_ROOT = await pki.x509.sign(Object.assign({ subject: "root-old", subjectPublicKey: OLDK.spki }, VALID), { key: OLDK.key, name: "root-old", publicKey: OLDK.spki });
  var NEW_ROOT = await pki.x509.sign(Object.assign({ subject: "root-new", subjectPublicKey: NEWK.spki }, VALID), { key: NEWK.key, name: "root-new", publicKey: NEWK.spki });
  var NEW_WITH_OLD = await pki.x509.sign(Object.assign({ subject: "root-new", subjectPublicKey: NEWK.spki }, VALID), { key: OLDK.key, cert: OLD_ROOT });
  var OLD_WITH_NEW = await pki.x509.sign(Object.assign({ subject: "root-old", subjectPublicKey: OLDK.spki }, VALID), { key: NEWK.key, cert: NEW_ROOT });
  var rootUpd = B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(NEW_WITH_OLD))]);
  var s165 = mk([H.genpOf("rootCaKeyUpdate", rootUpd)]);
  var r165 = await s165.session.info({ rootCaCert: OLD_ROOT });
  check("165a. info({rootCaCert}) accepts a rootCaKeyUpdate response (a DIFFERENT infoType, sec. 4.3.2)", r165.outcome === "answered" && r165.operation === "rootCaCert");
  check("165b. newWithNew + newWithOld are surfaced", r165.value.newWithNew.equals(NEW_ROOT) && r165.value.newWithOld.equals(NEW_WITH_OLD) && r165.value.oldWithNew === null);
  var genm165 = sentRr(s165.transport, 0);
  check("165c. the genm names id-it-rootCaCert and carries the certificate being updated", genm165[0].name === "rootCaCert" && Buffer.isBuffer(genm165[0].value));
  var allThree = B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(NEW_WITH_OLD)), B.explicit(1, B.raw(OLD_WITH_NEW))]);
  var r165d = await mk([H.genpOf("rootCaKeyUpdate", allThree)]).session.info({ rootCaCert: OLD_ROOT });
  check("165d. the OPTIONAL oldWithNew is surfaced when the responder sends it", r165d.value.oldWithNew.equals(OLD_WITH_NEW));
  // The relationships ARE the mechanism, so each is refused on its own. Every certificate below is
  // valid and parses; only the link the profile names is missing.
  check("165e. a newWithOld certifying some other key -> refused (it must carry the NEW root key)", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(OLD_WITH_NEW))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  // Carries the new key, but self-signed under the NEW key rather than signed by the old root, so
  // an entity trusting only the old root cannot reach it.
  check("165f. a newWithOld not signed by the OLD root -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(NEW_ROOT))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  check("165g. an oldWithNew certifying some other key -> refused (it must carry the OLD root key)", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(NEW_WITH_OLD)), B.explicit(1, B.raw(NEW_WITH_OLD))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  check("165h. an oldWithNew not signed by the NEW root -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(NEW_WITH_OLD)), B.explicit(1, B.raw(OLD_ROOT))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  // newWithNew is what the caller would install, so for a self-issued root its own signature is the
  // only thing vouching for the name and validity it carries.
  var brokenNewRoot = H.corruptLeafSig(NEW_ROOT);
  check("165j. a self-issued newWithNew whose own signature is broken -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(brokenNewRoot), B.explicit(0, B.raw(NEW_WITH_OLD))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  // A rollover signature is a BIT STRING; a valid one is octet-aligned (no unused bits). A newWithOld
  // whose signature declares an unused (zero) bit still parses and its octets still verify, but the path
  // verifier refuses this shape before the engine (guard.crypto.isOctetAligned) -- so the rollover
  // verifier must too. Built by re-signing until the signature ends in a zero bit (so declaring one
  // unused bit stays valid DER), then declaring that bit unused via surgery on the signature BIT STRING.
  var nonAlignedNwo = null;
  for (var oaTry = 0; oaTry < 60 && nonAlignedNwo === null; oaTry++) {
    var oaCand = await pki.x509.sign(Object.assign({ subject: "root-new", subjectPublicKey: NEWK.spki }, VALID), { key: OLDK.key, cert: OLD_ROOT });
    var oaSig = pki.asn1.read.bitString(pki.asn1.decode(oaCand).children[2]).bytes;
    if ((oaSig[oaSig.length - 1] & 1) === 0) {
      nonAlignedNwo = DS.patch(oaCand, function (node, path) {
        if (path.length === 1 && path[0].index === 2 && node.tagClass === "universal" && node.tagNumber === pki.asn1.TAGS.BIT_STRING) {
          return B.bitString(oaSig, 1);   // same octets, one unused (zero) bit -> not octet-aligned
        }
        return undefined;
      });
    }
  }
  check("165s. a newWithOld whose signature declares an unused (zero) bit -> refused (not octet-aligned; the path verifier refuses this shape)", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(nonAlignedNwo))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  // sec. 4.3.2 extends the operation to a directly trusted NON-root certificate, whose issuer this
  // message does not carry. Its own signature is unverifiable from here, and the new key is still
  // authenticated by newWithOld, so the update is accepted rather than refused for a check that
  // cannot be run.
  // NEW_INT names int-new, carries the new key and is issued by the old root, so it serves as both
  // the replacement certificate and the one the old root signed for it.
  var NEW_INT = await pki.x509.sign(Object.assign({ subject: "int-new", subjectPublicKey: NEWK.spki }, VALID), { key: OLDK.key, cert: OLD_ROOT });
  var r165k = await mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_INT), B.explicit(0, B.raw(NEW_INT))]))]).session.info({ rootCaCert: OLD_ROOT });
  check("165k. a NON-self-issued newWithNew is accepted (its issuer is not in this message)", r165k.outcome === "answered" && r165k.value.newWithNew.equals(NEW_INT));
  // The identity attack: a certificate the old CA legitimately issued for the new key, under some
  // OTHER name, satisfies key equality and signature validity. Pairing it with a self-signed
  // certificate of one's own choosing would otherwise read as the authority's own rollover.
  // The same names, the same key and a valid old-root signature, but issued as an end entity. It
  // cannot sign anything, so the authority this update claims to move would not arrive.
  // No keyUsage at all, so only the basicConstraints half can refuse it.
  var EE_FOR_NEW_KEY = await pki.x509.sign({ subject: "root-new", subjectPublicKey: NEWK.spki,
    notBefore: VALID.notBefore, notAfter: VALID.notAfter }, { key: OLDK.key, cert: OLD_ROOT });
  check("165o. a newWithOld issued as an END ENTITY -> refused (the update moves CA authority)", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(EE_FOR_NEW_KEY))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  var CA_NO_CERTSIGN = await pki.x509.sign({ subject: "root-new", subjectPublicKey: NEWK.spki,
    notBefore: VALID.notBefore, notAfter: VALID.notAfter,
    extensions: { basicConstraints: { cA: true }, keyUsage: ["cRLSign"] } }, { key: OLDK.key, cert: OLD_ROOT });
  check("165p. a newWithOld whose keyUsage withholds keyCertSign -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(CA_NO_CERTSIGN))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  // A CA certificate MUST mark basicConstraints critical (RFC 5280 sec. 4.2.1.9): a relying party
  // that skips extensions it does not recognize would not see the cA bit. The path validator refuses
  // a non-critical cA:TRUE, and a certificate this update transfers CA authority to is held to the
  // same bar. Everything else about this newWithOld is valid -- it carries the new key, names root-new
  // and is signed by the old root -- so only the criticality can refuse it. x509.sign will not emit a
  // non-critical CA basicConstraints, so the flag is dropped off a valid rollover and the modified
  // tbsCertificate re-signed with the old root key, keeping the signature _assertSignedBy checks valid.
  var flippedBc = _dropExtCritical(NEW_WITH_OLD, "basicConstraints");
  var flippedBcNode = pki.asn1.decode(flippedBc), flippedBcTbs = DS.reencode(flippedBcNode.children[0]);
  var CA_NONCRIT_BC = B.sequence([B.raw(flippedBcTbs), DS.reencode(flippedBcNode.children[1]),
    B.bitString(crypto.sign("sha256", flippedBcTbs, OLDK.keyObject), 0)]);
  check("165r. a newWithOld whose basicConstraints is non-critical -> refused (RFC 5280 sec. 4.2.1.9)", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(CA_NONCRIT_BC))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  // The authority check reads the two extensions by OID. pki.oid.register replaces a display name,
  // so a check asking whether an extension is NAMED basicConstraints would read a present one as
  // absent after a rename and refuse every valid update.
  var bcOid = pki.oid.byName("basicConstraints"), kuOid = pki.oid.byName("keyUsage");
  pki.oid.register(bcOid, "renamed-basic-constraints");
  pki.oid.register(kuOid, "renamed-key-usage");
  try {
    var r165q = await mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(NEW_WITH_OLD))]))]).session.info({ rootCaCert: OLD_ROOT });
    check("165q. a rollover is accepted even when basicConstraints and keyUsage are renamed via pki.oid.register", r165q.outcome === "answered");
  } finally { pki.oid.register(bcOid, "basicConstraints"); pki.oid.register(kuOid, "keyUsage"); }
  var STRAY_FOR_NEW_KEY = await pki.x509.sign(Object.assign({ subject: "device-42", subjectPublicKey: NEWK.spki }, VALID), { key: OLDK.key, cert: OLD_ROOT });
  check("165l. a newWithOld naming a DIFFERENT subject than newWithNew -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(STRAY_FOR_NEW_KEY))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  // And a certificate for the new root name, carrying the new key, signed by an authority that is
  // not the old root the request named.
  var OTHERK = signing.makeSigner("ec-p256", { cn: "other-ca" });
  var OTHER_ROOT = await pki.x509.sign(Object.assign({ subject: "other-ca", subjectPublicKey: OTHERK.spki }, VALID), { key: OTHERK.key, name: "other-ca", publicKey: OTHERK.spki });
  var NEW_BY_OTHER = await pki.x509.sign(Object.assign({ subject: "root-new", subjectPublicKey: NEWK.spki }, VALID), { key: OTHERK.key, cert: OTHER_ROOT });
  check("165m. a newWithOld signed by an authority other than the requested old root -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(NEW_BY_OTHER))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  // Signed by the OLD key and naming the new root as its subject, so both the signature check and
  // the subject check pass; only the issuer FIELD names someone else. RFC 5280 chains on that name,
  // so a certificate that does not claim the old root as its issuer is not a link from it.
  var MISNAMED_ISSUER = await pki.x509.sign(Object.assign({ subject: "root-new", subjectPublicKey: NEWK.spki }, VALID), { key: OLDK.key, name: "other-ca", publicKey: OLDK.spki });
  check("165n. a newWithOld whose issuer FIELD is not the old root -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(MISNAMED_ISSUER))]))]).session.info({ rootCaCert: OLD_ROOT }))));
  check("165i. an update answered for a DIFFERENT old root than the request named -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", rootUpd)]).session.info({ rootCaCert: NEW_ROOT }))));
  check("166. a RootCaKeyUpdateContent omitting newWithOld -> refused (sec. 4.3.2 over the 9480 syntax)", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", B.sequence([B.raw(NEW_ROOT)]))]).session.info({ rootCaCert: OLD_ROOT }))));
  var badNewWithOld = B.sequence([B.raw(NEW_ROOT), B.explicit(0, B.raw(B.sequence([B.sequence([B.integer(1n)])])))]);
  check("166b. a RootCaKeyUpdateContent whose newWithOld is not a certificate -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaKeyUpdate", badNewWithOld)]).session.info({ rootCaCert: OLD_ROOT }))));
  // The value here is a WELL-FORMED RootCaKeyUpdateContent, so nothing but the infoType check can
  // refuse it: sec. 4.3.2 answers id-it-rootCaCert with id-it-rootCaKeyUpdate, and a response
  // echoing the request OID is a different operation's answer.
  check("167. a response echoing the REQUEST infoType (rootCaCert) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("rootCaCert", rootUpd)]).session.info({ rootCaCert: OLD_ROOT }))));

  // ===== 168/169/170. certReqTemplate (sec. 4.3.3): the response certTemplate MUST omit publicKey,
  //                    serialNumber, signingAlg, issuerUID and subjectUID; keySpec is constrained. =====
  var CT = pki.crmf.buildCertTemplate;
  var okTemplate = B.sequence([B.raw(CT({ subject: [{ commonName: "device" }] }))]);
  var r168ok = await mk([H.genpOf("certReqTemplate", okTemplate)]).session.info({ certReqTemplate: true });
  check("168a. a conforming certReqTemplate response is answered with its certTemplate", r168ok.outcome === "answered" && r168ok.value.certTemplate != null && r168ok.value.keySpec === null);
  // sec. 4.3.3 makes an EMPTY name component and a NULL-DN meaningful in a template ("the EE SHOULD
  // fill in a value"), so a conforming response carries values the request builder would refuse to
  // author. Both must survive this read, or the operation rejects the CA it was asked to consult.
  var cnOid = pki.oid.byName("commonName");
  function bareTemplate(subjectDer) { return B.sequence([B.explicit(5, subjectDer)]); }
  function cnName(v) { return B.sequence([B.set([B.sequence([B.oid(cnOid), B.printable(v)])])]); }
  var r168c = await mk([H.genpOf("certReqTemplate", B.sequence([B.raw(bareTemplate(cnName("")))]))]).session.info({ certReqTemplate: true });
  check("168c. a certTemplate whose commonName is the empty string is ACCEPTED (sec. 4.3.3: the EE fills it in)", r168c.outcome === "answered" && r168c.value.certTemplate.subject.dn === "CN=");
  var r168d = await mk([H.genpOf("certReqTemplate", B.sequence([B.raw(bareTemplate(B.sequence([])))]))]).session.info({ certReqTemplate: true });
  check("168d. a certTemplate whose subject is the NULL-DN is ACCEPTED (sec. 4.3.3)", r168d.outcome === "answered" && r168d.value.certTemplate.subject.dn === "");
  var withKey = B.sequence([B.raw(CT({ subject: [{ commonName: "x" }], publicKey: CLIENT.spki }))]);
  check("168b. a certTemplate carrying publicKey -> refused (sec. 4.3.3: MUST be omitted)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", withKey)]).session.info({ certReqTemplate: true }))));
  var withSerial = B.sequence([B.raw(CT({ subject: [{ commonName: "x" }], serialNumber: 5n }))]);
  check("169. a certTemplate carrying serialNumber -> refused (sec. 4.3.3: MUST be omitted)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", withSerial)]).session.info({ certReqTemplate: true }))));
  function keySpec(oidName, valueDer) { return B.sequence([B.raw(CT({ subject: [{ commonName: "x" }] })), B.sequence([B.sequence([B.oid(pki.oid.byName(oidName)), valueDer])])]); }
  var okSpec = keySpec("rsaKeyLen", B.integer(2048n));
  var r170ok = await mk([H.genpOf("certReqTemplate", okSpec)]).session.info({ certReqTemplate: true });
  check("170a. a keySpec of one rsaKeyLen control is surfaced", Array.isArray(r170ok.value.keySpec) && r170ok.value.keySpec.length === 1 && r170ok.value.keySpec[0].rsaKeyLen === 2048n);
  check("170b. a keySpec rsaKeyLen of 0 -> refused (sec. 4.3.3: MUST be a positive integer)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("rsaKeyLen", B.integer(0n)))]).session.info({ certReqTemplate: true }))));
  check("170c. a keySpec control outside {algId, rsaKeyLen} -> refused (sec. 4.3.3)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("regToken", B.utf8("t")))]).session.info({ certReqTemplate: true }))));
  // The same for a control the registry does not name at all, so the refusal does not depend on the
  // OID resolving to something this toolkit happens to know.
  var unknownCtrl = B.sequence([B.raw(CT({ subject: [{ commonName: "x" }] })), B.sequence([B.sequence([B.oid("1.3.6.1.4.1.99999.1"), B.utf8("t")])])]);
  check("170c2. a keySpec control whose OID is not in the registry -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", unknownCtrl)]).session.info({ certReqTemplate: true }))));
  // AlgorithmIdentifier is SEQUENCE { algorithm, parameters OPTIONAL } and nothing after it. A
  // shape test that reads only the first child would pass a three-field SEQUENCE and hand the
  // caller an algorithm requirement no conforming responder can have written.
  var overlongAlgId = B.sequence([B.oid(pki.oid.byName("ecPublicKey")), B.nullValue(), B.nullValue()]);
  check("170e. a keySpec algId with a third field -> refused (an AlgorithmIdentifier holds at most two)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", overlongAlgId))]).session.info({ certReqTemplate: true }))));
  var ecAlgId = B.sequence([B.oid(pki.oid.byName("ecPublicKey")), B.oid(pki.oid.byName("prime256v1"))]);
  var r170f = await mk([H.genpOf("certReqTemplate", keySpec("algId", ecAlgId))]).session.info({ certReqTemplate: true });
  check("170f. a conforming algId keySpec is surfaced with its algorithm resolved", r170f.value.keySpec[0].algorithmName === "ecPublicKey" && Buffer.isBuffer(r170f.value.keySpec[0].algorithmParameters));
  // The stateful hash-based public keys (RFC 9802) are non-RSA public-key algorithms an entity can be
  // asked to generate, so a conforming template requiring one is surfaced, not rejected. Params are
  // absent for these, so only the resolved name is asserted.
  var rHbsHss = await mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("id-alg-hss-lms-hashsig"))])))]).session.info({ certReqTemplate: true });
  check("170s. a keySpec algId naming id-alg-hss-lms-hashsig is surfaced (RFC 9802 stateful HBS)", rHbsHss.value.keySpec[0].algorithmName === "id-alg-hss-lms-hashsig");
  var rHbsXmss = await mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("id-alg-xmss-hashsig"))])))]).session.info({ certReqTemplate: true });
  check("170t. a keySpec algId naming id-alg-xmss-hashsig is surfaced", rHbsXmss.value.keySpec[0].algorithmName === "id-alg-xmss-hashsig");
  var rHbsXmssmt = await mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("id-alg-xmssmt-hashsig"))])))]).session.info({ certReqTemplate: true });
  check("170u. a keySpec algId naming id-alg-xmssmt-hashsig is surfaced", rHbsXmssmt.value.keySpec[0].algorithmName === "id-alg-xmssmt-hashsig");
  check("170g. a keySpec rsaKeyLen whose value is not an INTEGER -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("rsaKeyLen", B.utf8("2048")))]).session.info({ certReqTemplate: true }))));
  check("170h. a keySpec algId whose value is not a SEQUENCE -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.integer(1n)))]).session.info({ certReqTemplate: true }))));
  // "Other than RSA" covers the whole PKCS#1 arc, so every spelling a responder could reach for is
  // refused, not just the generic key OID.
  check("170i. a keySpec algId naming rsassaPss -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("rsassaPss"))])))]).session.info({ certReqTemplate: true }))));
  check("170j. a keySpec algId naming sha256WithRSAEncryption -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("sha256WithRSAEncryption")), B.nullValue()])))]).session.info({ certReqTemplate: true }))));
  // RSA is registered on three arcs, so an arc test is not the rule. These two sit outside PKCS#1.
  check("170l. a keySpec algId naming id-rsa-kem -> refused (RSA off the PKCS#1 arc)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("id-rsa-kem"))])))]).session.info({ certReqTemplate: true }))));
  check("170m. a keySpec algId naming id-kem-rsa -> refused (RSA on the ISO arc)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("id-kem-rsa"))])))]).session.info({ certReqTemplate: true }))));
  // "Other than RSA" is decided by OID FAMILY: every OID under the PKCS#1 arc is RSA, so a standardized
  // member this registry has not named is refused with the ones it has. These OIDs (sha1/md5/sha224
  // WithRSAEncryption) are not registered here, so they exercise the arc classifier, not a hand-list.
  check("170m2. a keySpec algId naming sha1WithRSAEncryption (unregistered, under the PKCS#1 arc) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.2.840.113549.1.1.5")])))]).session.info({ certReqTemplate: true }))));
  check("170m3. a keySpec algId naming md5WithRSAEncryption (unregistered PKCS#1) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.2.840.113549.1.1.4")])))]).session.info({ certReqTemplate: true }))));
  check("170m4. a keySpec algId naming sha224WithRSAEncryption (unregistered PKCS#1) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.2.840.113549.1.1.14")])))]).session.info({ certReqTemplate: true }))));
  // RSA also sits off PKCS#1 on arcs shared with non-RSA algorithms, where no prefix isolates it, so
  // those OIDs are listed by name: the NIST RSASSA-PKCS1-v1_5-with-SHA-3 set (its arc holds ML-DSA too)
  // and the RFC 8692 RSASSA-PSS-with-SHAKE pair. Each must still be refused.
  check("170m5. a keySpec algId naming id-rsassa-pkcs1-v1_5-with-sha3-256 -> refused (NIST arc, shared with ML-DSA)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("id-rsassa-pkcs1-v1_5-with-sha3-256"))])))]).session.info({ certReqTemplate: true }))));
  check("170m6. a keySpec algId naming id-RSASSA-PSS-SHAKE256 -> refused (RFC 8692, PKIX arc)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("id-RSASSA-PSS-SHAKE256"))])))]).session.info({ certReqTemplate: true }))));
  // A NIST-arc NON-RSA neighbor (ML-DSA-65) on the SAME arc must still be SURFACED -- the arc is shared,
  // so the explicit RSA list must not spill onto its siblings.
  check("170m7. a keySpec algId naming id-ml-dsa-65 (NIST arc, non-RSA) is still surfaced", (await mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("id-ml-dsa-65"))])))]).session.info({ certReqTemplate: true })).value.keySpec[0].algorithmName === "id-ml-dsa-65");
  // The legacy OIW RSA-with-hash signatures (id-secsig arc, shared with DSA and the SHA-1 hash) are RSA
  // too and must be refused.
  check("170m8. a keySpec algId naming the OIW sha1WithRSASignature (1.3.14.3.2.29) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("sha1WithRSASignature"))])))]).session.info({ certReqTemplate: true }))));
  check("170m9. a keySpec algId naming the OIW md2WithRSASignature -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("md2WithRSASignature"))])))]).session.info({ certReqTemplate: true }))));
  // The OIW Secsig arc (1.3.14.3.2) is shared with DES, DSA, and the hashes, so no prefix isolates RSA:
  // every RSA member standardized under it is named and refused individually. md5WithRSA (.3),
  // rsaSignature (.11, the ISO 9796 scheme), and shaWithRSAEncryption (.15) are the members beyond the
  // md2/md5/sha1-WithRSASignature set.
  check("170m13. a keySpec algId naming the OIW md5WithRSA (1.3.14.3.2.3) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("md5WithRSA"))])))]).session.info({ certReqTemplate: true }))));
  check("170m14. a keySpec algId naming the OIW rsaSignature (1.3.14.3.2.11) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("rsaSignature"))])))]).session.info({ certReqTemplate: true }))));
  check("170m15. a keySpec algId naming the OIW shaWithRSAEncryption (1.3.14.3.2.15) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("shaWithRSAEncryption")), B.nullValue()])))]).session.info({ certReqTemplate: true }))));
  // Precision: a NON-RSA OIW sibling on the same shared arc (dsaWithSHA, 1.3.14.3.2.13) is SURFACED, not
  // refused -- the arc is enumerated by RSA member, not rejected wholesale, so a legitimate non-RSA algId
  // under it still reaches the caller (unregistered here, so its algorithmName is null).
  var r170oiwDsa = await mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.14.3.2.13")])))]).session.info({ certReqTemplate: true });
  check("170m16. a keySpec algId naming a non-RSA OIW sibling (dsaWithSHA) is surfaced, not refused", r170oiwDsa.outcome === "answered" && r170oiwDsa.value.keySpec[0].algorithmName === null);
  // A frozen conformance corpus of every RSA algorithm identifier the standard object tables name, across
  // the RSA-dedicated arcs (PKCS#1, TeleTrusT -- prefix-matched, so the whole family incl. unregistered
  // siblings) and the mixed arcs where RSA shares space with non-RSA algorithms (OIW Secsig, NIST
  // signature, PKIX, X.500 directory -- each member named). A keySpec algId naming any of them states an
  // RSA requirement that RFC 9483 sec. 4.3.3 forbids, so each MUST be refused. Frozen here so a newly
  // standardized RSA OID the classifier misses fails this test rather than reaching a responder unrefused.
  var RSA_OID_CORPUS = [
    "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.2", "1.2.840.113549.1.1.3", "1.2.840.113549.1.1.4",
    "1.2.840.113549.1.1.5", "1.2.840.113549.1.1.6", "1.2.840.113549.1.1.7", "1.2.840.113549.1.1.10",
    "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13", "1.2.840.113549.1.1.14",
    "1.2.840.113549.1.1.15", "1.2.840.113549.1.1.16",
    "1.3.14.3.2.2", "1.3.14.3.2.3", "1.3.14.3.2.4", "1.3.14.3.2.11", "1.3.14.3.2.14", "1.3.14.3.2.15",
    "1.3.14.3.2.22", "1.3.14.3.2.24", "1.3.14.3.2.25", "1.3.14.3.2.29",
    "2.16.840.1.101.3.4.3.13", "2.16.840.1.101.3.4.3.14", "2.16.840.1.101.3.4.3.15", "2.16.840.1.101.3.4.3.16",
    "2.5.8.1.1", "2.5.8.3.1", "2.5.8.3.100", "1.3.36.3.3.1.2", "1.2.156.10197.1.504",
    "0.4.0.127.0.7.2.2.2.1.1", "0.4.0.127.0.7.2.2.2.1.4", "0.4.0.127.0.7.2.2.2.1.6",
    "0.4.0.127.0.7.2.2.2.1.99",   // an UNREGISTERED id-TA-RSA sibling -- refused by arc prefix, proving the dedicated-arc match
    "1.3.6.1.5.5.7.6.30", "1.3.6.1.5.5.7.6.31",
    // TeleTrusT signatureScheme arc (1.3.36.3.4): the ISO/IEC 9796-2 RSA signature-with-message-recovery
    // schemes. Every node is RSA-based (integer factorization), so a keySpec algId naming one states an RSA
    // requirement sec. 4.3.3 forbids. The .4.2 (deterministic) and .4.3 (randomized) sub-arcs are RSA-
    // dedicated and prefix-matched, so every descendant -- named or not -- is caught; the bare arc nodes
    // (.4.2, .4.3, .4.1) sit at the arc length the strict-descendant match skips, so they are named. .4.1 is
    // ISO/IEC 9796-1 (also RSA) on the same registrant arc.
    "1.3.36.3.4.1", "1.3.36.3.4.1.1",
    "1.3.36.3.4.2", "1.3.36.3.4.2.1", "1.3.36.3.4.2.2",
    "1.3.36.3.4.2.2.1", "1.3.36.3.4.2.2.2", "1.3.36.3.4.2.2.3", "1.3.36.3.4.2.2.4", "1.3.36.3.4.2.2.5", "1.3.36.3.4.2.2.6",
    "1.3.36.3.4.3", "1.3.36.3.4.3.1", "1.3.36.3.4.3.2",
    "1.3.36.3.4.3.2.1", "1.3.36.3.4.3.2.2", "1.3.36.3.4.3.2.3", "1.3.36.3.4.3.2.4", "1.3.36.3.4.3.2.5", "1.3.36.3.4.3.2.6",
  ];
  var rsaCorpusResults = await Promise.all(RSA_OID_CORPUS.map(function (od) {
    return codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(od)])))]).session.info({ certReqTemplate: true })).then(function (code) { return { od: od, code: code }; });
  }));
  var rsaMisses = rsaCorpusResults.filter(function (r) { return !/^cmp\//.test(r.code || ""); }).map(function (r) { return r.od + "(" + r.code + ")"; });
  check("170m17. every standardized RSA algorithm OID (across all arcs) is refused in a keySpec algId -- misses: [" + rsaMisses.join(", ") + "]", rsaMisses.length === 0);
  // The corpus above is only meaningful if non-RSA algorithms on the SAME mixed arcs are NOT refused:
  // a classifier that refused everything would pass 170m17 while breaking a legitimate keySpec. Each of
  // these is surfaced (answered), so the refusals above are RSA-specific, not blanket.
  // mgf1 (1.2.840.113549.1.1.8) and pSpecified (.9) sit UNDER the prefix-matched PKCS#1 arc but are not RSA
  // algorithms (a mask-generation function and the OAEP label source), so they must be surfaced, not swept
  // in by the prefix -- the RSA_ARC_EXCLUDE carve-out. Listed here among the non-RSA controls that a keySpec
  // algId surfaces rather than refuses.
  var NONRSA_OID_CONTROLS = ["1.3.14.3.2.13", "1.3.14.3.2.26", "1.2.840.10045.4.3.2", "2.16.840.1.101.3.4.3.18", "1.3.101.112",
    "1.2.840.113549.1.1.8", "1.2.840.113549.1.1.9",
    // TeleTrusT signatureScheme precision: the RSA-dedicated 9796-2 sub-arcs (.4.2, .4.3) are prefix-matched,
    // but neither the PARENT signatureScheme node (.4) nor the sibling authentication-scheme arc (.5) is, so
    // an unassigned node directly under the parent and an ECC authentication node under .5.3 both stay
    // surfaced. If either were swept in, the classifier would have over-broadened past the RSA sub-arcs.
    "1.3.36.3.4.99",     // unassigned sibling directly under the parent signatureScheme arc (.4) -- parent not prefix-matched
    "1.3.36.3.5.3.2"];   // an ECC authentication-scheme node under the sibling .5 arc -- not RSA, not matched
  var nonRsaResults = await Promise.all(NONRSA_OID_CONTROLS.map(function (od) {
    return mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(od)])))]).session.info({ certReqTemplate: true }).then(function (r) { return { od: od, outcome: r.outcome }; }, function () { return { od: od, outcome: "THREW" }; });
  }));
  var nonRsaWrong = nonRsaResults.filter(function (r) { return r.outcome !== "answered"; }).map(function (r) { return r.od + "(" + r.outcome + ")"; });
  check("170m18. non-RSA algorithms on the shared arcs are surfaced, not refused -- wrong: [" + nonRsaWrong.join(", ") + "]", nonRsaWrong.length === 0);
  // The TeleTrusT signatureScheme arc (1.3.36.3.4) carries the ISO/IEC 9796-2 RSA signature-with-message-
  // recovery schemes. Every scheme is RSA-based, so a keySpec algId naming one states an RSA requirement
  // sec. 4.3.3 forbids and MUST be refused -- the same "other than RSA" rule as PKCS#1. The .4.2
  // (deterministic) and .4.3 (randomized) sub-arcs are RSA-dedicated and prefix-matched, so a named leaf, a
  // deep member, and an unregistered sibling are all caught; the bare arc nodes are named in RSA_OFF_ARC
  // because the strict-descendant match skips them. Distinct classification paths, each refused:
  check("170m19. a keySpec algId naming ISO 9796-2 deterministic-with-SHA-256 (1.3.36.3.4.2.2.4) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.36.3.4.2.2.4")])))]).session.info({ certReqTemplate: true }))));
  check("170m20. a keySpec algId naming ISO 9796-2 randomized-with-SHA-256 (1.3.36.3.4.3.2.4) -> refused (the .4.3 sub-arc, not only .4.2)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.36.3.4.3.2.4")])))]).session.info({ certReqTemplate: true }))));
  // The .2.1 / .3.1 nodes are the even-public-exponent RSA variants (registrant sigS_ISO9796-2Withrsa_even-exp,
  // marked "not used"). ISO/IEC 9796-2 is an integer-factorization (RSA) standard with no non-RSA member, so
  // these ARE RSA and MUST be refused -- the sub-arc prefix classifies them correctly, not over-broadly.
  check("170m21. a keySpec algId naming the deterministic even-exponent RSA variant (1.3.36.3.4.2.1) -> refused (RSA, registrant Withrsa_even-exp)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.36.3.4.2.1")])))]).session.info({ certReqTemplate: true }))));
  check("170m21b. a keySpec algId naming the randomized even-exponent RSA variant (1.3.36.3.4.3.1) -> refused (RSA)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.36.3.4.3.1")])))]).session.info({ certReqTemplate: true }))));
  check("170m22. a keySpec algId naming the 9796-2 hash-unspecified node (1.3.36.3.4.2.2) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.36.3.4.2.2")])))]).session.info({ certReqTemplate: true }))));
  check("170m23. a keySpec algId naming the 9796-2 deterministic BARE arc node (1.3.36.3.4.2) -> refused (RSA_OFF_ARC; the strict-descendant prefix skips the arc node itself)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.36.3.4.2")])))]).session.info({ certReqTemplate: true }))));
  check("170m24. a keySpec algId naming the 9796-2 randomized BARE arc node (1.3.36.3.4.3) -> refused (RSA_OFF_ARC)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.36.3.4.3")])))]).session.info({ certReqTemplate: true }))));
  // ISO/IEC 9796-1 (1.3.36.3.4.1) is on the same registrant arc and is likewise an RSA signature scheme,
  // so it is refused too: the "other than RSA" rule holds for the whole arc, not the 9796-2 subset the OID
  // family is titled for.
  check("170m25. a keySpec algId naming ISO 9796-1 (1.3.36.3.4.1) -> refused (RSA on the same registrant arc)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.36.3.4.1")])))]).session.info({ certReqTemplate: true }))));
  // Registration landed as classification metadata: the name resolves to its dotted OID. No sign/verify path
  // dispatches on a 9796-2 scheme OID (sign-scheme keys on the rsaEncryption key OID, not the scheme), so
  // this row classifies a keySpec requirement -- it is not a claim the toolkit can produce a 9796-2 signature.
  check("170m26. sigS-ISO9796-2Withrsa-sha256 resolves in the registry (1.3.36.3.4.2.2.4)", pki.oid.byName("sigS-ISO9796-2Withrsa-sha256") === "1.3.36.3.4.2.2.4");
  check("170m27. sigS-ISO9796-2rndWithrsa-sha512 resolves in the registry (1.3.36.3.4.3.2.6)", pki.oid.byName("sigS-ISO9796-2rndWithrsa-sha512") === "1.3.36.3.4.3.2.6");
  // The TeleTrusT rsaSignature arc (1.3.36.3.3.1) is RSA-dedicated, so it is prefix-matched: a named
  // member and an UNREGISTERED sibling on the same arc are both refused, proving the match catches the
  // whole family, not just the one OID the arc prefix was derived from.
  check("170m10. a keySpec algId naming rsaSignatureWithripemd160 (TeleTrusT) -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("rsaSignatureWithripemd160"))])))]).session.info({ certReqTemplate: true }))));
  check("170m11. a keySpec algId naming an UNREGISTERED TeleTrusT rsaSignature sibling (1.3.36.3.3.1.1) -> refused (arc-matched)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.36.3.3.1.1")])))]).session.info({ certReqTemplate: true }))));
  check("170m12. a keySpec algId naming the X.509 directory rsa OID (2.5.8.1.1) -> refused (distinct from PKCS#1)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("rsa"))])))]).session.info({ certReqTemplate: true }))));
  // An algorithm the registry cannot name is SURFACED, not refused: RFC 9480 sec. 2.16 holds the algId
  // to one rule -- other than RSA -- and the keySpec offers one control per algorithm the CA supports,
  // so the entity can pick a supported one. Refusing an unrecognized offer would fail the whole
  // exchange and drop the algorithms alongside it. It surfaces with its raw OID and a null name.
  var r170n = await mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.3.6.1.4.1.99999.7")])))]).session.info({ certReqTemplate: true });
  check("170n. a keySpec algId the registry does not name is surfaced with a null name (RFC 9480 sec. 2.16)", r170n.outcome === "answered" && r170n.value.keySpec[0].algorithm === "1.3.6.1.4.1.99999.7" && r170n.value.keySpec[0].algorithmName === null);
  // The multi-offer model (RFC 9483 sec. 4.3.3: "one AttributeTypeAndValue per supported algorithm"):
  // a keySpec offering a KNOWN non-RSA algorithm alongside an unrecognized one surfaces BOTH, so the
  // entity can pick the one it supports. One unrecognized offer must not fail the whole exchange.
  var multiKeySpec = B.sequence([B.raw(CT({ subject: [{ commonName: "x" }] })), B.sequence([
    B.sequence([B.oid(pki.oid.byName("algId")), B.sequence([B.oid(pki.oid.byName("id-ml-dsa-65"))])]),
    B.sequence([B.oid(pki.oid.byName("algId")), B.sequence([B.oid("1.3.6.1.4.1.99999.7")])]),
  ])]);
  var r170v = await mk([H.genpOf("certReqTemplate", multiKeySpec)]).session.info({ certReqTemplate: true });
  check("170v. a keySpec offering ML-DSA-65 AND an unrecognized OID surfaces BOTH, not refuses the exchange", r170v.outcome === "answered" && r170v.value.keySpec.length === 2 && r170v.value.keySpec[0].algorithmName === "id-ml-dsa-65" && r170v.value.keySpec[1].algorithmName === null && r170v.value.keySpec[1].algorithm === "1.3.6.1.4.1.99999.7");
  // pki.oid.register overrides an OID's forward display name, so a check that asked whether the
  // NAME said RSA would answer no for a renamed rsaEncryption while the algorithm was unchanged.
  // The identifiers are read at load, which is before any caller can re-register one.
  pki.oid.register(pki.oid.byName("rsaEncryption"), "genericPublicKey");
  check("170o. a renamed rsaEncryption is still refused (the identifier decides, not the label)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid("1.2.840.113549.1.1.1"), B.nullValue()])))]).session.info({ certReqTemplate: true }))));
  pki.oid.register("1.2.840.113549.1.1.1", "rsaEncryption");   // put the label back for later checks
  check("170k. a keySpec algId naming rsaesOaep -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("rsaesOaep"))])))]).session.info({ certReqTemplate: true }))));
  var rsaAlgId = B.sequence([B.oid(pki.oid.byName("rsaEncryption")), B.nullValue()]);
  check("170d. a keySpec algId naming RSA -> refused (sec. 4.3.3: MUST give an algorithm other than RSA)", /^cmp\//.test(await codeOf(mk([H.genpOf("certReqTemplate", keySpec("algId", rsaAlgId))]).session.info({ certReqTemplate: true }))));

  // ===== 171/172. crlUpdate (sec. 4.3.4): id-it-crlStatusList out, id-it-crls back; the issuer
  //                choice is a directoryName GeneralName, and thisUpdate is omitted when absent. =====
  var crlsValue = B.sequence([B.raw(REAL_CRL)]);
  var s171 = mk([H.genpOf("crls", crlsValue)]);
  // REAL_CRL is signed under CLIENT's certificate, so its issuer is CN=client -- the source this
  // request has to name for the answer to be an answer to it.
  var CRL_ISSUER = [{ commonName: "client" }];
  var r171 = await s171.session.info({ crlUpdate: { issuer: CRL_ISSUER } });
  check("171a. info({crlUpdate}) -> answered with the returned CRL list", r171.outcome === "answered" && Array.isArray(r171.value) && r171.value.length === 1);
  var genm171 = sentRr(s171.transport, 0);
  check("171b. the genm names id-it-crlStatusList (the response names id-it-crls)", genm171[0].name === "crlStatusList");
  var cs171 = pki.asn1.decode(genm171[0].value);
  check("171c. the CRLStatusListValue is a sequence of ONE CRLStatus (sec. 4.3.4)", cs171.children.length === 1);
  check("171d. thisUpdate is OMITTED when the EE holds no instance of the CRL (sec. 4.3.4)", cs171.children[0].children.length === 1);
  check("171e. the source is the issuer [1] arm carrying a directoryName GeneralName", cs171.children[0].children[0].tagClass === "context" && cs171.children[0].children[0].tagNumber === 1);
  var s172 = mk([H.genpOf("crls", crlsValue)]);
  await s172.session.info({ crlUpdate: { issuer: CRL_ISSUER, thisUpdate: new Date("2025-06-01T00:00:00Z") } });
  check("172a. a supplied thisUpdate is carried in the CRLStatus", pki.asn1.decode(sentRr(s172.transport, 0)[0].value).children[0].children.length === 2);
  // A certificate is a well-formed SEQUENCE and is not a CertificateList; answering a CRL request
  // with one would hand back something no revocation check can read.
  check("172a2. a crlUpdate answered with a certificate rather than a CRL -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("crls", B.sequence([B.raw(H.caCert)]))]).session.info({ crlUpdate: { issuer: [{ commonName: "c" }] } }))));
  // sec. 4.3.4 answers with the latest CRL FROM THE REFERENCED SOURCE, and only when it is newer
  // than a supplied thisUpdate. A CRL for some other issuer, or one no newer, answers a different
  // question, and the response is required to carry no value at all rather than that one.
  check("172a3. a CRL from an issuer other than the one the request named -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { issuer: [{ commonName: "some-other-ca" }] } }))));
  check("172a4. a CRL no newer than the supplied thisUpdate -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { issuer: CRL_ISSUER, thisUpdate: new Date("2026-06-01T00:00:00Z") } }))));
  check("172a5. a CRL exactly AT the supplied thisUpdate is not more recent -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { issuer: CRL_ISSUER, thisUpdate: new Date("2026-01-01T00:00:00Z") } }))));
  // sec. 4.3.4: the response represents the LATEST CRL from the single source the request named -- exactly
  // one. The id-it-crls list is SIZE (1..MAX), so a responder could return several valid CRLs from that
  // issuer; accepting them all would surface an older CRL beside the latest and let a caller act on a stale
  // value[0]. A multi-CRL response to this single-source query is refused. (Both entries here are the same
  // valid CRL from the named issuer, so only the one-per-query rule -- not issuer/freshness -- can reject.)
  check("172a5b. a crlUpdate response carrying TWO CRLs is refused (a single-source query answers with exactly one)", /^cmp\//.test(await codeOf(mk([H.genpOf("crls", B.sequence([B.raw(REAL_CRL), B.raw(REAL_CRL)]))]).session.info({ crlUpdate: { issuer: CRL_ISSUER } }))));
  // The comparison happens after the transport round-trip, so the instant is taken when the request
  // is built. A caller still holding that Date must not be able to move the bar under the answer.
  var movingDate = new Date("2026-06-01T00:00:00Z");
  var s172a7 = mk([function () { movingDate.setUTCFullYear(2020); return H.genpOf("crls", crlsValue); }]);
  check("172a7. a caller mutating the thisUpdate Date mid-transaction does not move the freshness bar", /^cmp\//.test(await codeOf(s172a7.session.info({ crlUpdate: { issuer: CRL_ISSUER, thisUpdate: movingDate } }))));
  // A dpn is a pointer the responder resolves internally, and a CRL claiming to be its issuer's
  // COMPLETE list states no scope at all (RFC 5280 sec. 5.2.5), so a dpn on its own leaves nothing
  // to hold the answer to. The issuer is required with it, and an unbound request is refused here
  // rather than answered with a CRL from a CA nobody named.
  check("172a6. a crlUpdate naming a dpn and no issuer -> cmp/bad-input", await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { dpn: { fullName: [{ uri: "http://ca.example/ca.crl" }] } } })) === "cmp/bad-input");
  // A CRL that DOES say which point it speaks for is held to the one that was asked for. sec. 4.3.4
  // points at exactly that field for where a distribution point name comes from, and sec. 5.2.5
  // pins the comparison to the identical encoding.
  var DP_ASKED = "http://ca.example/shard-1.crl", DP_OTHER = "http://ca.example/shard-2.crl";
  async function shardCrl(uri) {
    return pki.crl.sign({
      thisUpdate: new Date("2026-01-01T00:00:00Z"), nextUpdate: new Date("2026-02-01T00:00:00Z"), crlNumber: 2n,
      extensions: { issuingDistributionPoint: { fullName: [{ uniformResourceIdentifier: uri }] } },
    }, { key: CLIENT.key, cert: CLIENT.cert });
  }
  var shardAsked = B.sequence([B.raw(await shardCrl(DP_ASKED))]);
  var shardOther = B.sequence([B.raw(await shardCrl(DP_OTHER))]);
  var r172a8 = await mk([H.genpOf("crls", shardAsked)]).session.info({ crlUpdate: { dpn: { fullName: [{ uri: DP_ASKED }] }, issuer: CRL_ISSUER } });
  check("172a8. a CRL scoped to the requested distribution point -> answered", r172a8.outcome === "answered" && r172a8.value.length === 1);
  check("172a9. a CRL scoped to a DIFFERENT distribution point -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("crls", shardOther)]).session.info({ crlUpdate: { dpn: { fullName: [{ uri: DP_ASKED }] }, issuer: CRL_ISSUER } }))));
  // One name in common is the rule: a point published under several names shares one of them with a
  // reference that lists only that one, and demanding all would reject the point's own CRL.
  var r172a10 = await mk([H.genpOf("crls", shardAsked)]).session.info({ crlUpdate: { dpn: { fullName: [{ uri: DP_OTHER }, { uri: DP_ASKED }] }, issuer: CRL_ISSUER } });
  check("172a10. a request naming several names corresponds when ONE of them matches", r172a10.outcome === "answered");
  // sec. 5.2.5 marks issuingDistributionPoint critical, and the path validator will not build
  // distribution-point coverage from a non-critical one -- a relying party may ignore it. A crlUpdate
  // answer is held to the same line: a scope a verifier could ignore cannot bind the CRL to the point
  // the request named. crl.sign refuses to EMIT a non-critical IDP, so the flag is dropped off a valid
  // shard; the CRL's own signature over tbsCertList is not verified on this path (the CMP message
  // protection already authenticated the response), so it does not need re-signing.
  var nonCritIdpCrl = _dropExtCritical(await shardCrl(DP_ASKED), "issuingDistributionPoint");
  check("172a12. a CRL whose issuingDistributionPoint is non-critical -> refused (RFC 5280 sec. 5.2.5)", /^cmp\//.test(await codeOf(mk([H.genpOf("crls", B.sequence([B.raw(nonCritIdpCrl)]))]).session.info({ crlUpdate: { dpn: { fullName: [{ uri: DP_ASKED }] }, issuer: CRL_ISSUER } }))));
  // A dpn request always carries an issuer (172a6 refuses a dpn alone), so the issuer binding applies even
  // to a complete CRL that states no scope: a no-issuingDistributionPoint CRL from an issuer OTHER than the
  // one named is refused, and cannot be installed as the answer to the requested point. REAL_CRL states no
  // IDP and is issued by CN=client, so naming a different issuer exercises exactly that path.
  check("172a13. a dpn request + a complete (no-IDP) CRL from the WRONG issuer -> refused (the issuer binds a dpn request too)", /^cmp\//.test(await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { dpn: { fullName: [{ uri: DP_ASKED }] }, issuer: [{ commonName: "some-other-ca" }] } }))));
  // A complete CRL (no IDP) from the CORRECT issuer answers a dpn request: RFC 5280 sec. 5.2.5 makes a
  // scopeless CRL the issuer's whole population, which covers any one distribution point of it, so it is a
  // valid -- superset -- answer to the point that was named.
  var r172a14 = await mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { dpn: { fullName: [{ uri: DP_ASKED }] }, issuer: CRL_ISSUER } });
  check("172a14. a dpn request + a complete (no-IDP) CRL from the correct issuer -> answered (a complete list covers the point, RFC 5280 sec. 5.2.5)", r172a14.outcome === "answered" && r172a14.value.length === 1);
  // The scan reads the FIRST issuingDistributionPoint, which is safe only because a CertificateList
  // carrying the extension twice is refused before any of it is read. The fixture duplicates the
  // scope that WOULD correspond, so a route that reached the second copy would answer rather than
  // refuse, and this fails the day the parser stops refusing a duplicate extension.
  var dupIdpCrl = (function (der) {
    var node = pki.asn1.decode(der), tbs = node.children[0], out = [], idpOid = pki.oid.byName("issuingDistributionPoint");
    for (var i = 0; i < tbs.children.length; i++) {
      var c = tbs.children[i];
      if (c.tagClass !== "context" || c.tagNumber !== 0) { out.push(B.raw(c.bytes)); continue; }
      var exts = c.children[0], kept = [], dup = null;
      for (var j = 0; j < exts.children.length; j++) {
        kept.push(B.raw(exts.children[j].bytes));
        if (pki.asn1.read.oid(exts.children[j].children[0]) === idpOid) dup = exts.children[j].bytes;
      }
      kept.push(B.raw(dup));
      out.push(B.explicit(0, B.sequence(kept)));
    }
    return B.sequence([B.raw(B.sequence(out)), B.raw(node.children[1].bytes), B.raw(node.children[2].bytes)]);
  })(await shardCrl(DP_ASKED));
  var e172a11 = await (async function () {
    try { await mk([H.genpOf("crls", B.sequence([B.raw(dupIdpCrl)]))]).session.info({ crlUpdate: { dpn: { fullName: [{ uri: DP_ASKED }] }, issuer: CRL_ISSUER } }); return null; }
    catch (e) { return e; }
  })();
  check("172a11. a CRL carrying issuingDistributionPoint twice is refused as a CertificateList", e172a11 !== null && e172a11.code === "cmp/bad-info-value" && /CertificateList/.test(e172a11.message));
  check("172b. a crlUpdate naming neither dpn nor issuer -> cmp/bad-input (sec. 4.3.4)", await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: {} })) === "cmp/bad-input");
  // The dpn arm of CRLSource: an EXPLICIT [0] wrapping a DistributionPointName, whose own fullName
  // [0] keeps the IMPLICIT tagging of the module it is imported from.
  var s172d = mk([H.genpOf("crls", crlsValue)]);
  await s172d.session.info({ crlUpdate: { dpn: { fullName: [{ uri: "http://ca.example/ca.crl" }] }, issuer: CRL_ISSUER } });
  var cs172d = pki.asn1.decode(sentRr(s172d.transport, 0)[0].value).children[0].children[0];
  check("172d. the dpn arm is the [0] CRLSource alternative wrapping a DistributionPointName", cs172d.tagClass === "context" && cs172d.tagNumber === 0 && cs172d.children[0].tagNumber === 0);
  check("172e. a crlUpdate.dpn without fullName -> cmp/bad-input", await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { dpn: {}, issuer: CRL_ISSUER } })) === "cmp/bad-input");
  check("172e2. a non-object crlUpdate.dpn -> cmp/bad-input", await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { dpn: 5, issuer: CRL_ISSUER } })) === "cmp/bad-input");
  var s172j = mk([H.genpOf("crls", crlsValue)]);
  await s172j.session.info({ crlUpdate: { dpn: { fullName: { uri: "http://ca.example/ca.crl" } }, issuer: CRL_ISSUER } });   // a lone GeneralName, not an array
  check("172j. a lone fullName GeneralName is accepted as a one-element GeneralNames", pki.asn1.decode(sentRr(s172j.transport, 0)[0].value).children[0].children[0].children[0].children.length === 1);
  check("172f. a crlUpdate.dpn.fullName that is empty -> cmp/bad-input", await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { dpn: { fullName: [] }, issuer: CRL_ISSUER } })) === "cmp/bad-input");
  check("172g. an unknown crlUpdate field -> cmp/bad-input", await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { issuer: [{ commonName: "c" }], bogus: 1 } })) === "cmp/bad-input");
  check("172h. a non-object crlUpdate -> cmp/bad-input", await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: 5 })) === "cmp/bad-input");
  // Delayed delivery applies to a support message too (sec. 4.4).
  var s172i = mk([H.errorWaiting(), H.pollRep(-1, 1), H.pollRep(-1, 1), H.pollRep(-1, 1)], { maxPolls: 2 });
  var r172i = await s172i.session.info({ caCerts: true });
  check("172i. a support message under delayed delivery reaches poll-timeout naming its operation", r172i.outcome === "poll-timeout" && r172i.operation === "caCerts" && r172i.polls === 2);
  // CRLSource is a CHOICE, so one alternative goes on the wire, and sec. 4.3.4 settles which: the
  // dpn "if the CRL distribution point name is available". A caller with both keeps the issuer as
  // the CA whose CRL they will accept, which is what binds an answer a dpn alone cannot bind.
  var s172c = mk([H.genpOf("crls", shardAsked)]);
  var r172c = await s172c.session.info({ crlUpdate: { dpn: { fullName: [{ uri: DP_ASKED }] }, issuer: CRL_ISSUER } });
  var cs172c = pki.asn1.decode(sentRr(s172c.transport, 0)[0].value).children[0].children[0];
  check("172c. a crlUpdate naming BOTH sends the dpn arm and is answered", r172c.outcome === "answered" && cs172c.tagClass === "context" && cs172c.tagNumber === 0);
  check("172c2. a complete CRL from a CA the request did not name -> refused once an issuer is named", /^cmp\//.test(await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { dpn: { fullName: [{ uri: DP_ASKED }] }, issuer: [{ commonName: "some-other-ca" }] } }))));
  var r172c3 = await mk([H.genpOf("crls", crlsValue)]).session.info({ crlUpdate: { dpn: { fullName: [{ uri: DP_ASKED }] }, issuer: CRL_ISSUER } });
  check("172c3. a complete CRL from the named CA answers a dpn request", r172c3.outcome === "answered" && r172c3.value.length === 1);
  // The same reduce-at-the-door rule on the operation itself: an accessor that names both on the
  // read the arm count is taken over, and only an issuer on the next, must not get a request on the
  // wire that no check ever saw.
  var flip172 = 0, moving172 = {};
  Object.defineProperty(moving172, "crlUpdate", { enumerable: true, get: function () {
    flip172 += 1;
    return flip172 === 1 ? { dpn: { fullName: [{ uri: DP_ASKED }] }, issuer: CRL_ISSUER } : { issuer: [{ commonName: "some-other-ca" }] };
  } });
  var s172k = mk([H.genpOf("crls", shardAsked)]);
  var r172k = await s172k.session.info(moving172);
  var cs172k = pki.asn1.decode(sentRr(s172k.transport, 0)[0].value).children[0].children[0];
  check("172k. an operation accessor cannot change the request between the arm count and the encoding",
    r172k.outcome === "answered" && cs172k.tagClass === "context" && cs172k.tagNumber === 0);

  // ===== 173/174/175/176. the genp shape and the info request doors =====
  check("173. a genp carrying two InfoTypeAndValue -> refused (sec. 4.3: a sequence of one)", /^cmp\//.test(await codeOf(mk([H.genpTwo("caCerts", "crls")]).session.info({ caCerts: true }))));
  check("174. a genp answering caCerts with a DIFFERENT infoType -> refused", /^cmp\//.test(await codeOf(mk([H.genpOf("crls", crlsValue)]).session.info({ caCerts: true }))));
  check("175a. an unknown info operation -> cmp/bad-input", await codeOf(mk([H.genpOf("caCerts")]).session.info({ notAnOperation: true })) === "cmp/bad-input");
  check("175b. TWO info operations in one request -> cmp/bad-input", await codeOf(mk([H.genpOf("caCerts")]).session.info({ caCerts: true, certReqTemplate: true })) === "cmp/bad-input");
  check("175c. a non-object info request -> cmp/bad-input", await codeOf(mk([H.genpOf("caCerts")]).session.info(null)) === "cmp/bad-input");
  // A misspelling set to null must not read as an omitted field: counting only non-null keys would
  // let { caCerts: true, caCert: null } through as a correctly written single-operation request.
  check("175d. an unknown info key set to NULL is still refused", await codeOf(mk([H.genpOf("caCerts")]).session.info({ caCerts: true, caCert: null })) === "cmp/bad-input");
  // The session sends the ONE arm it read out of the request, so a key it does not recognize would be
  // dropped rather than reaching pki.cmp.build's arm count. enroll names it at its own door.
  check("175e. an unknown enroll key set to NULL is refused", await codeOf(mk([H.pkiconf()]).session.enroll({ ir: H.irRequest(CLIENT.spki).ir, irr: null })) === "cmp/bad-input");
  check("175e2. and an unknown enroll key with a value is refused the same way", await codeOf(mk([H.pkiconf()]).session.enroll({ ir: H.irRequest(CLIENT.spki).ir, bogus: 1 })) === "cmp/bad-input");
  // caCerts and certReqTemplate send NO infoValue, so a value supplied to either would be dropped.
  check("175f. info({caCerts: <a certificate>}) -> cmp/bad-input (this genm carries no infoValue)", await codeOf(mk([H.genpOf("caCerts")]).session.info({ caCerts: H.caCert })) === "cmp/bad-input");
  // The rootCaCert request value IS a CMPCertificate. Refusing it here keeps a caller's mistake
  // local; sending it would consume the one-shot transaction to learn the same thing from the CA.
  var s175i = mk([H.genpOf("rootCaKeyUpdate", rootUpd)]);
  check("175f2. info({rootCaCert: <valid DER that is not a certificate>}) -> cmp/bad-input", await codeOf(s175i.session.info({ rootCaCert: B.nullValue() })) === "cmp/bad-input");
  check("175f3. that refusal does not engage the transport", s175i.transport.calls.length === 0);
  // This value goes back on the wire, so it takes the forms that carry their own bytes.
  var r175f4 = await mk([H.genpOf("rootCaKeyUpdate", rootUpd)]).session.info({ rootCaCert: pki.schema.x509.pemEncode(OLD_ROOT, "CERTIFICATE") });
  check("175f4. a PEM certificate is accepted for rootCaCert", r175f4.outcome === "answered");
  // The byte-source guard would refuse a parsed certificate anyway; the named branch exists so the
  // refusal SAYS why this argument differs from revoke's, which does take the parsed form.
  var e175f5 = null;
  try { await mk([H.genpOf("rootCaKeyUpdate", rootUpd)]).session.info({ rootCaCert: pki.schema.x509.parse(OLD_ROOT) }); }
  catch (e) { e175f5 = e; }
  check("175f5. an already-parsed certificate is refused, and the message says it keeps no source DER", e175f5 && e175f5.code === "cmp/bad-input" && /keeps no source DER/.test(e175f5.message));
  check("175f6. a string that is not PEM -> cmp/bad-input", await codeOf(mk([H.genpOf("rootCaKeyUpdate", rootUpd)]).session.info({ rootCaCert: "not a pem block" })) === "cmp/bad-input");
  // sec. 4.3.2: rootCaCert names the CURRENT root, a CA. An end-entity certificate is refused at the
  // door -- before the one-shot transaction -- because the response path verifies the rollover against
  // this certificate's key, so a non-CA here would let a cross-certificate read as a root rollover.
  check("175f7. info({rootCaCert: <an end-entity certificate>}) -> cmp/bad-input (the current root must be a CA)", await codeOf(mk([H.genpOf("rootCaKeyUpdate", rootUpd)]).session.info({ rootCaCert: EE_NOT_CA })) === "cmp/bad-input");
  check("175f8. that refusal does not engage the transport (it is caught before the request is sent)", (function () { var s = mk([H.genpOf("rootCaKeyUpdate", rootUpd)]); return s.session.info({ rootCaCert: EE_NOT_CA }).then(function () { return false; }, function () { return s.transport.calls.length === 0; }); })());
  // The keySpec algId is held to one rule -- other than RSA (RFC 9480 sec. 2.16) -- so a registered
  // non-RSA algorithm that is not a public-key type (a digest like sha256) is SURFACED, not refused:
  // the caller weighs whether the offer is a key type it can generate. Refusing it would need the
  // drift-prone key-algorithm allowlist this design replaced, the one that wrongly refused conforming
  // non-RSA public keys it did not happen to list.
  var r170digest = await mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("sha256"))])))]).session.info({ certReqTemplate: true });
  check("170p. a keySpec algId naming a digest (sha256) is surfaced, not refused (only RSA is excluded)", r170digest.outcome === "answered" && r170digest.value.keySpec[0].algorithmName === "sha256");
  var r170q = await mk([H.genpOf("certReqTemplate", keySpec("algId", B.sequence([B.oid(pki.oid.byName("id-ml-dsa-65"))])))]).session.info({ certReqTemplate: true });
  check("170q. a keySpec algId naming ML-DSA-65 is accepted", r170q.value.keySpec[0].algorithmName === "id-ml-dsa-65");
  check("175g. info({certReqTemplate: 'x'}) -> cmp/bad-input", await codeOf(mk([H.genpOf("certReqTemplate")]).session.info({ certReqTemplate: "x" })) === "cmp/bad-input");
  // pki.cmp.build's own rr door, reached directly rather than through the session, which resolves
  // the reason name at its own door first.
  function buildRr(rd) {
    return pki.cmp.build({ header: { sender: { directoryName: [{ commonName: "c" }] }, recipient: { directoryName: [] } }, body: { rr: [rd] } },
      { key: CLIENT.key, cert: CLIENT.cert });
  }
  var goodDetails = { issuer: OWN.issuer.bytes, serialNumber: OWN.serialNumber };
  check("175i. cmp.build refuses an unknown CRLReason name -> cmp/bad-rev-req", await codeOf(buildRr({ certDetails: goodDetails, crlEntryDetails: { reason: "nope" } })) === "cmp/bad-rev-req");
  check("175j. cmp.build refuses a non-object crlEntryDetails -> cmp/bad-rev-req", await codeOf(buildRr({ certDetails: goodDetails, crlEntryDetails: 5 })) === "cmp/bad-rev-req");
  check("175k. cmp.build refuses an unknown crlEntryDetails field -> cmp/bad-rev-req", await codeOf(buildRr({ certDetails: goodDetails, crlEntryDetails: { reason: "keyCompromise", why: 1 } })) === "cmp/bad-rev-req");
  check("175h. an unknown RevDetails field reaches cmp.build's door -> cmp/bad-rev-req", await codeOf(Promise.resolve().then(function () {
    return pki.cmp.build({ header: { sender: { directoryName: [{ commonName: "c" }] }, recipient: { directoryName: [] } },
      body: { rr: [{ certDetails: { issuer: OWN.issuer.bytes, serialNumber: OWN.serialNumber }, crlEntryDetails: { reason: "keyCompromise" }, bogus: 1 }] } },
    { key: CLIENT.key, cert: CLIENT.cert });
  })) === "cmp/bad-rev-req");
  check("176. an info answered by an ip -> cmp/unexpected-arm", await codeOf(mk([H.ip(0, 0, certDer)]).session.info({ caCerts: true })) === "cmp/unexpected-arm");
  // Residual uncovered branches in revoke() / info(), each verified rather than assumed:
  //   * the `e.isCmpError` split in the four translating catches -- one side runs (the guards raise
  //     CmpError), the other is the defense against a future inner call that does not.
  //   * `t.status || null` on the two rejected verdicts -- a rejection always carries a status,
  //     since that IS what classifies it.
  //   * the non-CmpError catch around a support-value reader and around the AlgorithmIdentifier
  //     reader -- both are runParse, which raises CmpError for every malformed input.
  //   * the _checkInfoValue fallthrough, which INFO_OPS's four rows each return before.
  var s176 = mk([H.errorBody(2, ["systemFailure"])]);
  var r176 = await s176.session.info({ caCerts: true });
  check("176b. a verified error body answering a genm -> outcome:rejected with its PKIStatusInfo", r176.outcome === "rejected" && r176.status.status.code === 2);

  console.log("CHECKS " + helpers.getChecks());
}

if (require.main === module) { run().catch(function (e) { console.error(e); process.exit(1); }); }
module.exports = { run: run };
