// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.ocsp: OCSP (RFC 6960) request build + response sign + client verify. Drives the
 * SHIPPED consumer paths pki.ocsp.buildRequest / .sign / .buildErrorResponse / .verify against a
 * REAL mini-CA (makeOcspWorld: the responder/delegate cert issuance signature is really verified),
 * round-tripping through pki.schema.ocsp.parse* and asserting the fail-closed verdicts. The
 * responder-cert reject family (RFC 6960 sec. 4.2.2.2) is the crown jewel: each MUST fail closed to
 * "unknown"/unauthorized, never a silent accept.
 */

var helpers = require("../helpers");
var check = helpers.check;
var pki = helpers.pki;
var world = require("../helpers/ocsp-world");
var derSurgery = require("../helpers/der-surgery");
var makeOcspWorld = world.makeOcspWorld;
var nameDN = world.nameDN;
var b = pki.asn1.build;
function O(n) { return pki.oid.byName(n); }
function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
async function codeOfAsync(fn) { try { await fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
function pemCert(der) { return "-----BEGIN CERTIFICATE-----\n" + Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "") + "\n-----END CERTIFICATE-----\n"; }

var TU = new Date("2027-01-01T00:00:00Z"), NU = new Date("2028-01-01T00:00:00Z"), T = new Date("2027-06-01T00:00:00Z");

// keyUsage BIT STRING for a bit set (digitalSignature=0).
function kuBits(bits) {
  var maxBit = Math.max.apply(null, bits), nBytes = (maxBit >> 3) + 1, buf = Buffer.alloc(nBytes);
  bits.forEach(function (p) { buf[p >> 3] |= (0x80 >> (p & 7)); });
  return b.bitString(buf, 7 - (maxBit & 7));
}

async function signGood(w, opts) {
  return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] },
    { cert: w.responderCertDer, key: w.responderKeyPkcs8 }, opts);
}
function verify(w, resp, extra) { return pki.ocsp.verify(resp, Object.assign({ cert: w.targetCertDer, issuer: w.issuerCertDer, time: T }, extra || {})); }

async function run() {
  var w = await makeOcspWorld("ec-p256");

  // ---- buildRequest ----
  var req = await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer });
  var pr = pki.schema.ocsp.parseRequest(req);

  // Dense caller-array hardening: a sparse batch of queries / responses is a typed ocsp/bad-input, caught
  // before the map reaches the hole as a native error.
  var _spQ = [{ cert: w.targetCertDer, issuer: w.issuerCertDer }]; _spQ[2] = _spQ[0];
  check("sparse buildRequest batch -> typed ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.buildRequest(_spQ); })) === "ocsp/bad-input");
  var _spR = [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }]; _spR[2] = _spR[0];
  check("sparse responses -> typed ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: _spR }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  // A caller date option of an unexpected type (a BigInt has no numeric Date form) is refused with the
  // typed ocsp/bad-input, not the native TypeError the Date constructor throws on a BigInt.
  check("BigInt thisUpdate -> typed ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: 1n, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  check("BigInt producedAt -> typed ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", producedAt: 1n, responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  var _goodResp = await signGood(w);
  check("BigInt verify time -> typed ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.verify(_goodResp, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: 1n }); })) === "ocsp/bad-input");
  check("buildRequest round-trips: one Request with the target serial",
    pr.requestList.length === 1 && pr.requestList[0].certID.serialNumberHex === pki.schema.x509.parse(w.targetCertDer).serialNumberHex);
  var reqN = await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { nonce: true });
  var prN = pki.schema.ocsp.parseRequest(reqN);
  var reqNonceExt = (prN.requestExtensions || []).filter(function (e) { return e.oid === O("ocspNonce"); })[0];
  check("buildRequest nonce:true embeds a 32-octet non-critical nonce", reqNonceExt && reqNonceExt.nonce.length === 32 && reqNonceExt.critical !== true);
  check("buildRequest a 0-octet nonce is rejected at build (RFC 9654 sec. 2.1)",
    (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { nonce: Buffer.alloc(0) }); })) === "ocsp/bad-input");
  check("buildRequest a 129-octet nonce is rejected",
    (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { nonce: Buffer.alloc(129) }); })) === "ocsp/bad-input");
  check("buildRequest signer without requestorName -> ocsp/bad-input (RFC 6960 sec. 4.1.2)",
    (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { signer: { cert: w.issuerCertDer, key: w.issuerKeyPkcs8 } }); })) === "ocsp/bad-input");
  check("buildRequest lightweight rejects a non-SHA-1 CertID",
    (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { profile: "lightweight", hashAlgorithm: "sha256" }); })) === "ocsp/bad-input");
  var multiReq = await pki.ocsp.buildRequest([{ cert: w.targetCertDer, issuer: w.issuerCertDer }, { cert: w.targetCertDer, issuer: w.issuerCertDer }]);
  check("buildRequest accepts an array of queries (one Request each)", pki.schema.ocsp.parseRequest(multiReq).requestList.length === 2);
  check("buildRequest with an empty query array -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.buildRequest([]); })) === "ocsp/bad-input");
  check("the lightweight profile permits exactly one Request", (await codeOfAsync(function () { return pki.ocsp.buildRequest([{ cert: w.targetCertDer, issuer: w.issuerCertDer }, { cert: w.targetCertDer, issuer: w.issuerCertDer }], { profile: "lightweight" }); })) === "ocsp/bad-input");
  check("a query missing issuer -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: w.targetCertDer }); })) === "ocsp/bad-input");

  // A CertID is built from three fields of the two certificates the query names, and
  // a parsed certificate may be passed instead of its bytes. An object missing one of
  // those fields must be refused at the door with this verb's own code -- the fields
  // are the CertID itself, so reaching the encoder with one absent produces either a
  // foreign fault from the ASN.1 layer or, for the issuer name, a request whose
  // issuerNameHash covers nothing.
  var parsedTarget = pki.schema.x509.parse(w.targetCertDer);
  var parsedIssuer = pki.schema.x509.parse(w.issuerCertDer);
  function lacking(certObj, field) {
    var c = Object.assign({}, certObj);
    var dot = field.indexOf(".");
    if (dot < 0) { delete c[field]; return c; }
    c[field.slice(0, dot)] = Object.assign({}, certObj[field.slice(0, dot)]);
    delete c[field.slice(0, dot)][field.slice(dot + 1)];
    return c;
  }
  check("buildRequest accepts the parser's own output for both certificates",
    pki.schema.ocsp.parseRequest(await pki.ocsp.buildRequest({ cert: parsedTarget, issuer: parsedIssuer })).requestList.length === 1);
  check("a query certificate without serialNumber -> ocsp/bad-input, not an asn1 fault",
    (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: lacking(parsedTarget, "serialNumber"), issuer: parsedIssuer }); })) === "ocsp/bad-input");
  check("an issuer certificate without issuer.bytes -> ocsp/bad-input, not a request naming no issuer",
    (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: parsedTarget, issuer: lacking(parsedIssuer, "issuer.bytes") }); })) === "ocsp/bad-input");
  check("an issuer certificate without subject.bytes -> ocsp/bad-input",
    (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: parsedTarget, issuer: lacking(parsedIssuer, "subject.bytes") }); })) === "ocsp/bad-input");

  // ---- sign -> verify per algorithm (the extracted sign-scheme's payoff) ----
  for (var alg of ["ec-p256", "rsa", "ed25519", "ml-dsa-65"]) {
    var wa = await makeOcspWorld(alg);
    var resp = await signGood(wa);
    var v = await verify(wa, resp);
    check("sign->verify (" + alg + ") -> good, authorized, signature valid",
      v.status === "good" && v.responderAuthorized === true && v.signatureValid === true);
  }

  // ---- certStatus arms + raw-exactness ----
  var good = await signGood(w);
  check("verify good", (await verify(w, good)).status === "good");
  // The canonical verdict alias: `valid` is the affirmative terminal and nothing more, so the
  // reason a certificate is not good stays in `status`.
  check("V78 a good response carries valid true beside its status", (await verify(w, good)).valid === true);
  var rev = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: { revoked: new Date("2027-03-01Z"), revocationReason: "keyCompromise" }, thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  var vr = await verify(w, rev);
  check("verify revoked surfaces the status + reason", vr.status === "revoked" && vr.revocationReason === "keyCompromise");
  check("V78 a revoked response is valid false, with the reason still in status", vr.valid === false && vr.status === "revoked");
  // `valid` is created as the verdict's OWN property. An assignment would run an inherited setter,
  // so a co-resident that installs one could swallow the write and leave its getter answering true
  // for a revoked certificate.
  check("V78 a polluted Object.prototype.valid cannot make a revoked response read as valid",
    await (async function () {
      var pending = verify(w, rev);            // options are read before the pollution lands
      Object.defineProperty(Object.prototype, "valid",
        { configurable: true, get: function () { return true; }, set: function () {} });
      try {
        var polluted = await pending;
        return Object.prototype.hasOwnProperty.call(polluted, "valid") && polluted.valid === false;
      } finally { delete Object.prototype.valid; }
    })());
  // Every field of the verdict is its own property, not `valid` alone: the affirmative boolean is
  // derived from `status`, so a swallowed `status` write would answer the derivation from the
  // inherited getter and report a revoked certificate as good.
  check("V78 a polluted Object.prototype.status cannot make a revoked response read as good",
    await (async function () {
      var pending = verify(w, rev);
      Object.defineProperty(Object.prototype, "status",
        { configurable: true, get: function () { return "good"; }, set: function () {} });
      try {
        var polluted = await pending;
        return Object.prototype.hasOwnProperty.call(polluted, "status") &&
          polluted.status === "revoked" && polluted.valid === false;
      } finally { delete Object.prototype.status; }
    })());
  // The lower-level verdict settles through a promise of its own, and resolving one reads `then`
  // off the value. That verdict ends the lookup on itself, so an accessor installed while the
  // target-certificate signature check is pending cannot rewrite its status before pki.ocsp.verify
  // copies it and derives valid.
  check("V78 an inherited then accessor cannot rewrite the status the low-level verdict settles with",
    await (async function () {
      var pending = verify(w, rev);            // options are read before the pollution lands
      Object.defineProperty(Object.prototype, "then", { configurable: true,
        get: function () { try { this.status = "good"; } catch (_e) { /* frozen */ } return undefined; } });
      try {
        var polluted = await pending;
        return polluted.status === "revoked" && polluted.valid === false;
      } finally { delete Object.prototype.then; }
    })());
  check("V78 a polluted Object.prototype.status cannot survive pki.path.verifyOcspResponse either",
    await (async function () {
      var pending = pki.path.verifyOcspResponse(rev, pki.schema.x509.parse(w.targetCertDer), pki.schema.x509.parse(w.issuerCertDer), T);
      Object.defineProperty(Object.prototype, "status",
        { configurable: true, get: function () { return "good"; }, set: function () {} });
      try {
        var polluted = await pending;
        return Object.prototype.hasOwnProperty.call(polluted, "status") &&
          polluted.status === "revoked" && polluted.valid === false;
      } finally { delete Object.prototype.status; }
    })());
  check("#78 verify revoked surfaces revocationTime (the LTV instant)", vr.revocationTime instanceof Date && vr.revocationTime.getTime() === new Date("2027-03-01Z").getTime());
  var unk = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "unknown", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("verify explicit unknown status", (await verify(w, unk)).status === "unknown");
  check("V78 an unknown response is valid false", (await verify(w, unk)).valid === false);
  // raw-exactness: mutate one byte of the signed response -> signature no longer verifies.
  var tampered = Buffer.from(good); tampered[tampered.length - 40] ^= 0x01;
  var vt = await verify(w, tampered);
  check("a mutated response byte -> signatureValid:false, status unknown", vt.status === "unknown" && vt.signatureValid === false);
  // A rejected response reports every field the verdict is derived from. Without that, a value
  // left on Object.prototype answers the read the evaluation never wrote, and a response whose
  // signature does not verify is reported as a good status the responder never gave.
  check("V78 a polluted Object.prototype.sawGood cannot turn a rejected response into good",
    await (async function () {
      var pending = verify(w, tampered);            // options are read before the pollution lands
      Object.defineProperty(Object.prototype, "sawGood",
        { value: true, enumerable: false, configurable: true, writable: true });
      try {
        var polluted = await pending;
        return polluted.status === "unknown" && polluted.valid === false && polluted.signatureValid === false;
      } finally { delete Object.prototype.sawGood; }
    })());

  // ---- version omitted + GeneralizedTime shape ----
  var rd = pki.asn1.decode(pki.schema.ocsp.parseResponse(good).basicResponse.tbsResponseDataBytes);
  check("ResponseData omits the DEFAULT version (first child is the responderID [1], not [0])",
    rd.children[0].tagClass === "context" && rd.children[0].tagNumber === 1);
  check("producedAt is GeneralizedTime YYYYMMDDHHMMSSZ (no fractional seconds)",
    rd.children[1].tagNumber === 24 && /^\d{14}Z$/.test(rd.children[1].content.toString("latin1")));

  // ---- nonce echo + match ----
  var goodN = await signGood(w, { nonce: Buffer.alloc(32, 7) });
  check("nonce echo + match -> nonceMatched true, good", (function (r) { return r.nonceMatched === true && r.status === "good"; })(await verify(w, goodN, { requestNonce: Buffer.alloc(32, 7) })));
  check("nonce mismatch -> fail closed to unknown", (await verify(w, goodN, { requestNonce: Buffer.alloc(32, 9) })).status === "unknown");
  check("a client that sent NO nonce ignores the response nonce (still good)", (await verify(w, goodN)).status === "good");
  // The field is three-state and always present: true bound, false not bound, null never asked.
  // Absent would make "not requested" indistinguishable from "this build does not report it".
  check("a client that sent no nonce still gets nonceMatched, as null",
    (function (r) { return "nonceMatched" in r && r.nonceMatched === null; })(await verify(w, goodN)));
  check("a client that sent a nonce gets a boolean, not null",
    (await verify(w, goodN, { requestNonce: Buffer.alloc(32, 7) })).nonceMatched === true);
  // The downgrade is for `good` ONLY. A revoked verdict does not expire the way a
  // non-revocation does, so discarding a signed, current, authorized `revoked`
  // because it was replayed would hand a soft-fail caller the very certificate the
  // responder refused -- the anti-replay defense becoming the thing that accepts it.
  var revokedN = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer,
    issuer: w.issuerCertDer, status: { revoked: new Date("2027-03-01Z"), revocationReason: "keyCompromise" },
    thisUpdate: TU, nextUpdate: NU }] },
  { cert: w.responderCertDer, key: w.responderKeyPkcs8 }, { nonce: Buffer.alloc(32, 7) });
  check("nonce mismatch does NOT downgrade a revoked verdict; it reports the mismatch",
    (function (r) { return r.status === "revoked" && r.nonceMatched === false && r.revocationReason === "keyCompromise"; })(
      await verify(w, revokedN, { requestNonce: Buffer.alloc(32, 9) })));
  check("...and a matching nonce on the same revoked response still reports revoked",
    (await verify(w, revokedN, { requestNonce: Buffer.alloc(32, 7) })).status === "revoked");

  // ---- buildErrorResponse ----
  var err = pki.ocsp.buildErrorResponse("tryLater");
  var pe = pki.schema.ocsp.parseResponse(err);
  check("buildErrorResponse('tryLater') -> status tryLater, no basicResponse (RFC 6960 sec. 2.3)",
    pe.responseStatus.name === "tryLater" && pe.basicResponse === null);
  check("buildErrorResponse rejects an unknown status", codeOf(function () { pki.ocsp.buildErrorResponse("bogus"); }) === "ocsp/bad-input");

  // The responder descriptor is the CALLER's object, and sign() defers: the
  // ResponderID and the embedded certificate are fixed from `cert` on the way
  // in, the signature is made several promise turns later. A `key` replaced in
  // that gap would produce a response naming one responder and signed by
  // another key -- which nothing could verify.
  var liveResponder = { cert: w.responderCertDer, key: w.responderKeyPkcs8 };
  var livePromise = pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, liveResponder);
  liveResponder.key = w.issuerKeyPkcs8;        // rewritten on the very next line
  check("a responder descriptor rewritten after the call still signs under the key its certificate names",
    (await verify(w, await livePromise)).status === "good");

  // ---- the responder-cert full-validation reject family (crown jewel) ----
  // CA-direct: the issuing CA signs its own response.
  var direct = await pki.ocsp.sign({ responderID: "byKey", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.issuerCertDer, key: w.issuerKeyPkcs8 }, { embedCert: false });
  check("authorized: issuing CA direct (byKey) -> good", (await verify(w, direct)).status === "good");
  // valid delegate already covered (signGood). Reject family:
  async function signWith(delegateDer) {
    return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: delegateDer, key: w.responderKeyPkcs8 });
  }
  var noEku = await w.delegate({ eku: null });
  check("reject: delegate WITHOUT id-kp-OCSPSigning EKU -> unauthorized, unknown", (function (r) { return r.responderAuthorized === false && r.status === "unknown"; })(await verify(w, await signWith(noEku))));
  var anyEku = await w.delegate({ eku: ["anyExtendedKeyUsage"] });
  check("reject: anyExtendedKeyUsage does NOT authorize -> unknown", (await verify(w, await signWith(anyEku))).status === "unknown");
  // Responder authorization is a decision about who may answer, so it must not be reachable through
  // the prototype: `indexOf` replaced after load reports id-kp-OCSPSigning present in a purpose list
  // that does not carry it, and a delegate the CA never authorized answers for the whole issuer.
  var anyEkuSigned = await signWith(anyEku);
  var realIndexOf = Array.prototype.indexOf;
  Array.prototype.indexOf = function () { return 0; };
  var anyEkuSwapped;
  try { anyEkuSwapped = await verify(w, anyEkuSigned); }
  finally { Array.prototype.indexOf = realIndexOf; }
  check("reject: ...and stays unauthorized with Array.prototype.indexOf replaced after load",
    anyEkuSwapped.responderAuthorized === false && anyEkuSwapped.status === "unknown");
  var noNocheck = await w.delegate({ nocheck: false });
  check("reject: delegate missing id-pkix-ocsp-nocheck -> unauthorized (RFC 6960 sec. 4.2.2.2.1)", (function (r) { return r.responderAuthorized === false && r.status === "unknown"; })(await verify(w, await signWith(noNocheck))));
  var expired = await w.delegate({ notAfter: new Date("2027-03-01Z") });   // valid window ends before T
  check("reject: expired delegate -> unauthorized", (await verify(w, await signWith(expired))).status === "unknown");
  var badKu = await w.delegate({ keyUsage: kuBits([2]) });   // keyEncipherment only, no digitalSignature
  check("reject: delegate keyUsage without digitalSignature -> unauthorized", (await verify(w, await signWith(badKu))).status === "unknown");
  // delegate issued by a DIFFERENT CA (wrong issuer / signed by another key).
  var altDelegate = await w.delegate({ issuerCN: "Other CA", issuerKey: w.altCaKeyObject });
  check("reject: delegate issued by a different CA -> unauthorized", (await verify(w, await signWith(altDelegate))).status === "unknown");
  // A SingleResponse carrying a critical unknown singleExtension MUST be treated as unusable.
  var critSingle = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU, singleExtensions: [b.sequence([b.oid("1.3.6.1.4.1.99999.1"), b.boolean(true), b.octetString(b.nullValue())])] }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("reject: a critical unknown singleExtension -> the SingleResponse is unusable, unknown", (await verify(w, critSingle)).status === "unknown");

  // ---- currency ----
  var future = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: new Date("2029-01-01Z"), nextUpdate: new Date("2030-01-01Z") }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("currency: thisUpdate in the future -> unusable, unknown", (await verify(w, future)).status === "unknown");
  var noNext = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: null }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("currency: no nextUpdate -> unbounded validity is not cacheable, unknown", (await verify(w, noNext)).status === "unknown");
  var stale = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: new Date("2025-01-01Z"), nextUpdate: new Date("2025-06-01Z") }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("currency: nextUpdate before now -> stale, unknown", (await verify(w, stale)).status === "unknown");

  // ---- issuer-substitution defense: bind the supplied issuer to the target cert ----
  // A rogue "issuer" that shares the real issuer's subject DN but a different key: it can build a
  // self-consistent CertID under its own key and sign a direct-responder good response. The verify
  // MUST reject it because the target certificate's signature does not verify under the rogue key.
  var rogueResp = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.rogueIssuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.rogueIssuerCertDer, key: w.rogueIssuerKeyPkcs8 }, { embedCert: false });
  check("a rogue issuer (matching subject DN, different key) is not accepted as the direct CA responder",
    (await pki.ocsp.verify(rogueResp, { cert: w.targetCertDer, issuer: w.rogueIssuerCertDer, time: T })).status === "unknown");
  check("pki.path.verifyOcspResponse rejects an unbound issuer (target signature does not verify under it)",
    (function (r) { return r.status === "unknown" && r.signatureValid === false; })(await pki.path.verifyOcspResponse(rogueResp, pki.schema.x509.parse(w.targetCertDer), pki.schema.x509.parse(w.rogueIssuerCertDer), T)));
  check("an issuer whose subject DN differs from the target's issuer is rejected (name binding)",
    (await verify(w, good, { cert: w.targetCertDer, issuer: w.altCaCertDer })).status === "unknown");

  // ---- CertID mismatch (cross-CA substitution defense) ----
  var wrongCertId = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.altCaCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("CertID mismatch: issuerKeyHash of a different CA -> not-about-this-cert, unknown", (await verify(w, wrongCertId)).status === "unknown");
  // The CertID binding is what says the response concerns THIS certificate, so it is decided with a
  // captured byte comparison: `Buffer.prototype.equals` replaced after load reports every hash
  // equal, and a `good` signed for a different CA answers for the certificate under check.
  var realEquals = Buffer.prototype.equals;
  Buffer.prototype.equals = function () { return true; };
  var wrongCertIdSwapped;
  try { wrongCertIdSwapped = await verify(w, wrongCertId); }
  finally { Buffer.prototype.equals = realEquals; }
  check("CertID mismatch: ...and stays unknown with Buffer.prototype.equals replaced after load",
    wrongCertIdSwapped.status === "unknown");

  // ---- signed request (optionalSignature) + requestorName forms ----
  var signedReq = await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer },
    { requestorName: nameDN("Requestor"), signer: { cert: w.responderCertDer, key: w.responderKeyPkcs8 } });
  var psr = pki.schema.ocsp.parseRequest(signedReq);
  check("a signed request carries requestorName + optionalSignature", psr.requestorName != null && psr.optionalSignature != null);
  var signedReq2 = await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer },
    { requestorName: { bytes: nameDN("Parsed Requestor") }, signer: { cert: pemCert(w.responderCertDer), key: w.responderKeyPkcs8 } });
  check("requestorName accepts a parsed Name ({bytes}) and the signer cert accepts PEM", pki.schema.ocsp.parseRequest(signedReq2).requestorName != null);
  // requestorName accepts any BufferSource DER Name, not only a Buffer: an ArrayBuffer names the same
  // requestor. Before the widening the one-form Buffer.isBuffer gate refused it (ocsp/bad-input).
  var _rnBuf = nameDN("AB Requestor");
  var _rnAB = new ArrayBuffer(_rnBuf.length); new Uint8Array(_rnAB).set(_rnBuf);
  var signedReqAB = await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer },
    { requestorName: _rnAB, signer: { cert: w.responderCertDer, key: w.responderKeyPkcs8 } });
  check("requestorName accepts an ArrayBuffer DER Name (#68 ocsp _nameDer 1-form widening)",
    pki.schema.ocsp.parseRequest(signedReqAB).requestorName != null);
  check("requestorName must be a DER Name Buffer or a parsed Name",
    (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { requestorName: 42 }); })) === "ocsp/bad-input");
  check("a signer cert given as a parsed certificate is rejected (needs DER/PEM to embed verbatim)",
    (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { requestorName: nameDN("R"), signer: { cert: pki.schema.x509.parse(w.responderCertDer), key: w.responderKeyPkcs8 } }); })) === "ocsp/bad-input");

  // ---- sign responder-cert input forms + option/validation arms ----
  var uResp = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] },
    { cert: new Uint8Array(w.responderCertDer), key: w.responderKeyPkcs8 });
  check("sign accepts a Uint8Array responder cert", (await verify(w, uResp)).status === "good");
  var pemResp = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] },
    { cert: pemCert(w.responderCertDer), key: w.responderKeyPkcs8 });
  check("sign accepts a PEM responder cert", (await verify(w, pemResp)).status === "good");
  check("sign rejects a parsed responder cert (needs DER/PEM to embed verbatim)",
    (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: pki.schema.x509.parse(w.responderCertDer), key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  check("sign rejects an invalid responderID", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "bogus", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good" }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  check("sign rejects a response entry with neither certID nor cert+issuer", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ status: "good" }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  check("sign rejects an unknown certStatus", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "bogus", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  // nextUpdate omitted (undefined, not null) -> a default ~7-day currency window keeps it usable.
  var recentTU = new Date(Date.now() - 3600 * 1000);
  var defNu = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: recentTU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  var pvDef = await pki.ocsp.verify(defNu, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: new Date() });
  check("nextUpdate omitted -> a default currency window makes the response usable", pvDef.status === "good" && pvDef.nextUpdate != null);

  // ---- nonce requested but the response carries none -> fail closed ----
  check("requestNonce set but the response has no nonce -> unknown (nonce not echoed)",
    (await verify(w, good, { requestNonce: Buffer.alloc(32, 3) })).status === "unknown");

  // ---- input/option micro-branches ----
  check("buildRequest pem:true emits a PEM OCSP REQUEST string", typeof (await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { pem: true })) === "string");
  check("a responder cert given as an undecodable PEM -> ocsp/bad-input",
    (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: "-----BEGIN CERTIFICATE-----\nnot valid base64 !!!\n-----END CERTIFICATE-----\n", key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  check("sign with null responseData -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign(null, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  var strTU = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: "2027-01-01T00:00:00Z", nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("thisUpdate accepted as an ISO date string (coerced via new Date())", (await verify(w, strTU)).status === "good");

  // ---- producedAt is a ResponseData field (read from responseData, honored) ----
  var prodResp = await pki.ocsp.sign({ responderID: "byName", producedAt: new Date("2027-05-01T00:00:00Z"), responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  var prodRd = pki.asn1.decode(pki.schema.ocsp.parseResponse(prodResp).basicResponse.tbsResponseDataBytes);
  check("producedAt supplied in responseData is honored, not defaulted to now", /^20270501000000Z$/.test(prodRd.children[1].content.toString("latin1")));

  // ---- an unparseable date fails closed at sign, never a malformed signed response ----
  check("sign with an unparseable thisUpdate -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: "not a date", nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  check("sign with an unparseable producedAt -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", producedAt: "whenever", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  check("sign with an unparseable revocation date -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: { revoked: "sometime" }, thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");

  // ---- requestNonce accepts a Uint8Array of the echoed bytes (input-form parity) ----
  check("requestNonce accepts a Uint8Array of the echoed nonce -> nonceMatched", (await verify(w, goodN, { requestNonce: new Uint8Array(Buffer.alloc(32, 7)) })).nonceMatched === true);

  // ---- CertID hashAlgorithm parameters: NULL for SHA-1, ABSENT for SHA-2 (RFC 5754) ----
  function certIdOf(reqDer) { return pki.asn1.decode(reqDer).children[0].children[0].children[0].children[0]; }
  check("a SHA-1 CertID hashAlgorithm carries NULL parameters", certIdOf(await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer })).children[0].children.length === 2);
  check("a SHA-256 CertID hashAlgorithm omits parameters (RFC 5754)", certIdOf(await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { hashAlgorithm: "sha256" })).children[0].children.length === 1);

  // ---- sign-scheme faults surface as ocsp/* (the domain error factory) ----
  check("a non-key responder key -> ocsp/bad-input (routed through the sign-scheme error factory)",
    (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: 42 }); })) === "ocsp/bad-input");

  // ---- verify accepts DER/PEM responses + Buffer/Uint8Array/PEM cert & issuer ----
  var pemResponse = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }, { pem: true });
  check("verify accepts a PEM response + Uint8Array cert + PEM issuer", (await pki.ocsp.verify(pemResponse, { cert: new Uint8Array(w.targetCertDer), issuer: pemCert(w.issuerCertDer), time: T })).status === "good");
  check("verify rejects a non-certificate opts.cert -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.verify(good, { cert: 42, issuer: w.issuerCertDer, time: T }); })) === "ocsp/bad-input");
  check("verify rejects a non-decodable response -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.verify(42, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T }); })) === "ocsp/bad-input");
  check("verify rejects an undecodable PEM cert -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.verify(good, { cert: "-----BEGIN CERTIFICATE-----\nnot b64 !!!\n-----END CERTIFICATE-----\n", issuer: w.issuerCertDer, time: T }); })) === "ocsp/bad-input");
  check("verify rejects a well-formed-DER but non-certificate cert -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.verify(good, { cert: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]), issuer: w.issuerCertDer, time: T }); })) === "ocsp/bad-input");
  check("verify accepts a Uint8Array response", (await pki.ocsp.verify(new Uint8Array(good), { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T })).status === "good");
  check("verify rejects an undecodable PEM response -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.verify("-----BEGIN OCSP RESPONSE-----\nnot b64 !!!\n-----END OCSP RESPONSE-----\n", { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T }); })) === "ocsp/bad-input");
  check("buildRequest with an unsupported CertID hashAlgorithm -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { hashAlgorithm: "md5" }); })) === "ocsp/bad-input");

  // ---- verifyRequest: a responder verifies a client's signed OCSP request (RFC 6960 sec. 4.1.1) ----
  var reqSigner = { signer: { cert: w.issuerCertDer, key: w.issuerKeyPkcs8 }, requestorName: nameDN("OCSP Mini CA") };
  function mkSignedReq(cert) { return pki.ocsp.buildRequest({ cert: cert, issuer: w.issuerCertDer }, reqSigner); }
  // Rebuild a signed OCSPRequest with its optionalSignature carrying NO certs (RFC 6960 lets them
  // travel out of band). The signature is over tbsRequest, unchanged, so it still verifies.
  function stripCerts(reqDer) {
    var r = pki.asn1.decode(reqDer);                 // SEQ { tbsRequest, [0] EXPLICIT { Signature } }
    var s = r.children[1].children[0];               // Signature SEQ
    return b.sequence([b.raw(r.children[0].bytes), b.explicit(0, b.sequence([b.raw(s.children[0].bytes), b.raw(s.children[1].bytes)]))]);
  }
  var vrOk = await pki.ocsp.verifyRequest(await mkSignedReq(w.targetCertDer));
  check("VR1. a signed request verifies: signed + signatureValid, signerSubject decoded", vrOk.signed === true && vrOk.signatureValid === true && vrOk.signerSubject.dn === "CN=OCSP Mini CA");
  check("#78 valid = signed AND signatureValid on the ocsp.verifyRequest verdict", vrOk.valid === true && vrOk.valid === (vrOk.signed && vrOk.signatureValid));
  check("VR1b. signerCert is surfaced raw + requestList/version decoded", Buffer.compare(vrOk.signerCert, w.issuerCertDer) === 0 && vrOk.requestList.length === 1 && vrOk.version === 1);
  // VR2: splice tbsRequest of A onto the optionalSignature (over a DIFFERENT tbs) of B -> the
  // signature does not verify over the message's own tbsRequest.
  var da = pki.asn1.decode(await mkSignedReq(w.targetCertDer)), db = pki.asn1.decode(await mkSignedReq(w.responderCertDer));
  var spliced = b.sequence([b.raw(da.children[0].bytes), b.raw(db.children[1].bytes)]);
  var vrBad = await pki.ocsp.verifyRequest(spliced);
  check("VR2. a request whose signature does not match its tbsRequest -> signatureValid:false", vrBad.signed === true && vrBad.signatureValid === false);
  var vrUn = await pki.ocsp.verifyRequest(await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }));
  check("VR3. an unsigned request -> signed:false, signatureValid:false, no signerCert", vrUn.signed === false && vrUn.signatureValid === false && vrUn.signerCert === null);
  check("VR4. malformed bytes -> a typed OcspError", (await codeOfAsync(function () { return pki.ocsp.verifyRequest(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00])); })).indexOf("ocsp/") === 0);
  check("VR5. an unknown option -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.verifyRequest(spliced, { nope: 1 }); })) === "ocsp/bad-input");
  // VR6/VR7: a signed request that omits its own certs. opts.certs supplies the signer, or its
  // absence is reported rather than guessed.
  var noCerts = stripCerts(await mkSignedReq(w.targetCertDer));
  var vrOob = await pki.ocsp.verifyRequest(noCerts, { certs: [w.issuerCertDer] });
  check("VR6. a certs-less signed request verifies against opts.certs", vrOob.signed === true && vrOob.signatureValid === true);
  var vrNoCert = await pki.ocsp.verifyRequest(noCerts);
  check("VR7. a signed request with no cert and no opts.certs -> signatureValid:false, named reason", vrNoCert.signed === true && vrNoCert.signatureValid === false && vrNoCert.signerCert === null && /no certificate/.test(vrNoCert.reason));
  check("VR8. opts.certs accepts a PEM entry (input-form parity)", (await pki.ocsp.verifyRequest(noCerts, { certs: [pemCert(w.issuerCertDer)] })).signatureValid === true);
  check("VR9. a sparse opts.certs array -> ocsp/bad-input", (await codeOfAsync(function () { var a = []; a[2] = w.issuerCertDer; return pki.ocsp.verifyRequest(noCerts, { certs: a }); })) === "ocsp/bad-input");
  check("VR10. a non-certificate opts.certs entry -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.verifyRequest(noCerts, { certs: [42] }); })) === "ocsp/bad-input");
  check("VR11. verifyRequest accepts a PEM OCSP REQUEST string", (await pki.ocsp.verifyRequest(await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, Object.assign({ pem: true }, reqSigner)))).signatureValid === true);
  check("VR12. a valid-DER but non-certificate signer (opts.certs) -> ocsp/bad-signer-cert", (await codeOfAsync(function () { return pki.ocsp.verifyRequest(noCerts, { certs: [Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00])] }); })) === "ocsp/bad-signer-cert");
  // VR13: RFC 6960 sec. 4.1.1 certs is an unordered SEQUENCE OF Certificate. Rebuild the request so
  // its signer certificate is NOT first (a chain cert precedes it); the signer is still found.
  function reorderCerts(reqDer, certDers) {
    var r = pki.asn1.decode(reqDer), s = r.children[1].children[0];   // Signature SEQ
    var optSig = b.sequence([b.raw(s.children[0].bytes), b.raw(s.children[1].bytes), b.explicit(0, b.sequence(certDers.map(function (d) { return b.raw(d); })))]);
    return b.sequence([b.raw(r.children[0].bytes), b.explicit(0, optSig)]);
  }
  var reordered = reorderCerts(await mkSignedReq(w.targetCertDer), [w.responderCertDer, w.issuerCertDer]);   // signer (issuer) is second
  var vrReord = await pki.ocsp.verifyRequest(reordered);
  check("VR13. a signer certificate that is not first in certs still verifies", vrReord.signatureValid === true && Buffer.compare(vrReord.signerCert, w.issuerCertDer) === 0);
  // VR14: a malformed certificate embedded in the request is skipped (never fatal), so a valid
  // signer beside it still verifies -- unlike a malformed opts.certs entry (VR12), which is refused.
  var withJunk = reorderCerts(await mkSignedReq(w.targetCertDer), [Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]), w.issuerCertDer]);
  var vrJunk = await pki.ocsp.verifyRequest(withJunk);
  check("VR14. a malformed embedded cert is skipped, the valid signer beside it wins", vrJunk.signatureValid === true);
  check("VR14b. certs excludes the malformed entry (only parseable certs reach the path-build pool)", vrJunk.certs.length === 1 && Buffer.compare(vrJunk.certs[0], w.issuerCertDer) === 0);
  check("VR15. embedded certs none of which signed -> signatureValid:false (not a throw)", (await pki.ocsp.verifyRequest(reorderCerts(await mkSignedReq(w.targetCertDer), [w.responderCertDer]))).signatureValid === false);
  check("VR16. opts.certs supplied but none signed -> signatureValid:false", (await pki.ocsp.verifyRequest(noCerts, { certs: [w.responderCertDer] })).signatureValid === false);
  // VR17: the request bytes are snapshotted at the door, so a caller mutating the buffer across the
  // async signature check cannot make verification read bytes other than those parsed and reported.
  var reqBuf = Buffer.from(await mkSignedReq(w.targetCertDer));
  var vrPending = pki.ocsp.verifyRequest(reqBuf);
  reqBuf.fill(0);   // mutate the caller-owned buffer during the await window
  check("VR17. mutating the request buffer across the await does not change the verdict", (await vrPending).signatureValid === true);
  var certBuf = Buffer.from(w.issuerCertDer);
  var vrPending2 = pki.ocsp.verifyRequest(noCerts, { certs: [certBuf] });
  certBuf.fill(0);   // mutate the caller-owned opts.certs buffer during the await window
  check("VR18. mutating an opts.certs buffer across the await does not change the verdict", (await vrPending2).signatureValid === true);
  // VR19: several certificates in the (unordered) certs field share the signing key -- an expired
  // certificate beside its renewal. All verify; ALL are surfaced so the responder can pick a usable
  // one rather than being handed only whichever appears first.
  var caSpki = pki.schema.x509.parse(w.issuerCertDer).subjectPublicKeyInfo.bytes;
  var caTwin = await pki.x509.sign({ subject: "OCSP Mini CA (renewed)", subjectPublicKey: caSpki, notBefore: new Date("2027-01-01T00:00:00Z"), notAfter: new Date("2029-01-01T00:00:00Z") }, { key: w.issuerKeyPkcs8 });
  var vrMulti = await pki.ocsp.verifyRequest(reorderCerts(await mkSignedReq(w.targetCertDer), [w.issuerCertDer, caTwin]));
  check("VR19. multiple certs sharing the signing key -> signerCerts lists all matches", vrMulti.signatureValid === true && vrMulti.signerCerts.length === 2 && Buffer.compare(vrMulti.signerCert, vrMulti.signerCerts[0]) === 0);
  // VR20: a request embeds the signer plus a non-signing (intermediate) certificate. Only the signer
  // verifies, but `certs` surfaces the FULL embedded bag so the responder has the chain to path-validate.
  var withChain = reorderCerts(await mkSignedReq(w.targetCertDer), [w.issuerCertDer, w.responderCertDer]);
  var vrChain = await pki.ocsp.verifyRequest(withChain);
  check("VR20. certs surfaces the full embedded bag; signerCerts only the certs that signed", vrChain.signatureValid === true && vrChain.signerCerts.length === 1 && vrChain.certs.length === 2);
  // VR21: a non-signing certificate precedes the signer, and a same-key renewal follows it. The
  // signature verification stops at the first match; the renewal is then collected by public-key
  // comparison (not another verify), so signerCerts lists both signing certs and skips the non-signer.
  var vrPre = await pki.ocsp.verifyRequest(reorderCerts(await mkSignedReq(w.targetCertDer), [w.responderCertDer, w.issuerCertDer, caTwin]));
  check("VR21. non-signer skipped; signer + same-key renewal both in signerCerts", vrPre.signatureValid === true && vrPre.signerCerts.length === 2 && vrPre.certs.length === 3);
  // VR22: two certificates reuse an RSA key but encode the rsaEncryption AlgorithmIdentifier
  // differently -- one with NULL parameters (the canonical form pki.x509.sign emits), one with the
  // parameters absent. Both keys verify the same request signature, but their subjectPublicKeyInfo
  // DER differs, so membership is by the subjectPublicKey material rather than the whole SPKI, or the
  // absent-parameters twin is dropped from signerCerts even though it carries the signing key.
  var rsaKp = await pki.key.generate({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" });
  var rsaPkcs8 = await pki.key.export(rsaKp.privateKey);
  var rsaCert = await pki.x509.sign({ subject: "RSA OCSP Requestor", subjectPublicKey: await pki.key.export(rsaKp.publicKey), notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"), extensions: { basicConstraints: { cA: true }, keyUsage: ["digitalSignature", "keyCertSign"] } }, { key: rsaPkcs8 });
  var rsaTwin = derSurgery.patch(rsaCert, function (node) {
    if (derSurgery.isAlgId(node, O("rsaEncryption")) && node.children.length === 2) return pki.asn1.build.sequence([Buffer.from(node.children[0].bytes)]);
    return undefined;
  });
  var rsaReq = await pki.ocsp.buildRequest({ cert: rsaCert, issuer: rsaCert }, { signer: { cert: rsaCert, key: rsaPkcs8 }, requestorName: pki.schema.x509.parse(rsaCert).subject.bytes });
  var vrRsa = await pki.ocsp.verifyRequest(reorderCerts(rsaReq, [rsaCert, rsaTwin]));
  check("VR22. same RSA key under NULL vs absent params -> both in signerCerts", vrRsa.signatureValid === true && vrRsa.signerCerts.length === 2 && vrRsa.certs.length === 2);
  // VR23: a non-signing certificate carries the SAME key bytes as the signer under a DIFFERENT
  // algorithm -- an X25519 subjectPublicKey equal to the Ed25519 signer's 32-byte value. X25519
  // cannot verify the Ed25519 request signature, so membership binds the algorithm identity, not the
  // key bytes alone, and the coincident-key certificate is NOT reported as a signer.
  var edKp = await pki.key.generate("Ed25519");
  var edPkcs8 = await pki.key.export(edKp.privateKey);
  var edCert = await pki.x509.sign({ subject: "Ed OCSP Requestor", subjectPublicKey: await pki.key.export(edKp.publicKey), notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"), extensions: { basicConstraints: { cA: true }, keyUsage: ["digitalSignature", "keyCertSign"] } }, { key: edPkcs8 });
  var edSpkiTlv = pki.schema.x509.parse(edCert).subjectPublicKeyInfo.bytes;
  var x25519Spki = derSurgery.patch(edSpkiTlv, function (node) {
    if (derSurgery.isAlgId(node, O("Ed25519"))) return b.sequence([Buffer.from(pki.asn1.build.oid(O("X25519")))]);
    return undefined;
  });
  var x25519Twin = derSurgery.replaceTlv(edCert, edSpkiTlv, x25519Spki).der;
  var edReq = await pki.ocsp.buildRequest({ cert: edCert, issuer: edCert }, { signer: { cert: edCert, key: edPkcs8 }, requestorName: pki.schema.x509.parse(edCert).subject.bytes });
  var vrEd = await pki.ocsp.verifyRequest(reorderCerts(edReq, [edCert, x25519Twin]));
  check("VR23. coincident key bytes under a different algorithm -> not a signer", vrEd.signatureValid === true && vrEd.signerCerts.length === 1 && vrEd.certs.length === 2);
  // VR24: two ECDSA P-256 certificates carry the SAME key, one encoding the point uncompressed
  // (04||X||Y) and one compressed (02/03||X). Both verify the request, but their key bytes differ, so
  // membership is by verifying each candidate rather than comparing key bytes, or the compressed
  // encoding is dropped from signerCerts even though it carries the signing key.
  var ecKp = await pki.key.generate({ name: "ECDSA", namedCurve: "P-256" });
  var ecPkcs8 = await pki.key.export(ecKp.privateKey);
  var ecCert = await pki.x509.sign({ subject: "EC OCSP Requestor", subjectPublicKey: await pki.key.export(ecKp.publicKey), notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2028-01-01T00:00:00Z"), extensions: { basicConstraints: { cA: true }, keyUsage: ["digitalSignature", "keyCertSign"] } }, { key: ecPkcs8 });
  var ecSpkiTlv = pki.schema.x509.parse(ecCert).subjectPublicKeyInfo.bytes;
  var ecSpkiNode = pki.asn1.decode(ecSpkiTlv);
  var ecPoint = pki.asn1.read.bitString(ecSpkiNode.children[1]).bytes;   // 04 || X(32) || Y(32)
  var ecCompressed = Buffer.concat([Buffer.from([(ecPoint[64] & 1) ? 0x03 : 0x02]), ecPoint.slice(1, 33)]);
  var ecCompSpki = b.sequence([b.raw(ecSpkiNode.children[0].bytes), b.bitString(ecCompressed)]);
  var ecTwin = derSurgery.replaceTlv(ecCert, ecSpkiTlv, ecCompSpki).der;
  var ecReq = await pki.ocsp.buildRequest({ cert: ecCert, issuer: ecCert }, { signer: { cert: ecCert, key: ecPkcs8 }, requestorName: pki.schema.x509.parse(ecCert).subject.bytes });
  var vrEc = await pki.ocsp.verifyRequest(reorderCerts(ecReq, [ecCert, ecTwin]));
  check("VR24. same EC key compressed and uncompressed -> both in signerCerts", vrEc.signatureValid === true && vrEc.signerCerts.length === 2 && vrEc.certs.length === 2);

  // ---- certStatus state machine: default good, raw certID, and every revoked cell ----
  // status + thisUpdate BOTH omitted -> good [0] + a producedAt-now thisUpdate.
  var recent = new Date(Date.now() - 3600 * 1000);
  var bareGood = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, nextUpdate: new Date(Date.now() + 7 * 24 * 3600 * 1000) }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("a response entry with status + thisUpdate omitted defaults to good, now", (await pki.ocsp.verify(bareGood, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: new Date() })).status === "good");
  // a raw pre-built CertID (Buffer + Uint8Array) passes through verbatim.
  var reqNode = pki.asn1.decode(await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }));
  var rawCertId = reqNode.children[0].children[0].children[0].children[0].bytes;   // OCSPRequest > tbsRequest > requestList > Request > CertID
  var rawResp = await pki.ocsp.sign({ responderID: "byName", responses: [{ certID: rawCertId, status: "good", thisUpdate: recent, nextUpdate: new Date(Date.now() + 7 * 24 * 3600 * 1000) }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("a raw pre-built CertID Buffer round-trips + verifies good", (await pki.ocsp.verify(rawResp, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: new Date() })).status === "good");
  var rawRespU8 = await pki.ocsp.sign({ responderID: "byName", responses: [{ certID: new Uint8Array(rawCertId), status: "good", thisUpdate: recent, nextUpdate: new Date(Date.now() + 7 * 24 * 3600 * 1000) }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("a raw pre-built CertID Uint8Array round-trips + verifies good", (await pki.ocsp.verify(rawRespU8, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: new Date() })).status === "good");
  // A pre-encoded CertID is spliced in RAW, so a non-byte value must be refused rather
  // than coerced: Buffer.from(20) allocates twenty zero octets, which would put a
  // structurally broken CertID inside a response this responder then signs.
  check("a numeric certID is refused, never coerced to zero octets",
    (await codeOfAsync(function () {
      return pki.ocsp.sign({ responderID: "byName", responses: [{ certID: 20, status: "good", thisUpdate: recent, nextUpdate: new Date(Date.now() + 7 * 24 * 3600 * 1000) }] },
        { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
    })) === "ocsp/bad-input");
  // The responder key is read several promise turns after sign() returns, so PKCS#8 bytes
  // stay caller-owned across that gap. Capturing only the reference stops responder.key =
  // other but not a rewrite of the bytes themselves, which yields a response carrying this
  // responder's ID and certificate over a signature made by different key material -- one
  // no relying party can verify. Overwrite the buffer the way a pooled or zeroized key
  // would and the response must still verify.
  var mutableKey = Buffer.from(w.responderKeyPkcs8);
  var racedSignP = pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer,
    status: "good", thisUpdate: recent, nextUpdate: new Date(Date.now() + 7 * 24 * 3600 * 1000) }] },
  { cert: w.responderCertDer, key: mutableKey });
  mutableKey.fill(0);
  var racedSigned = await racedSignP;
  check("a responder key overwritten after the call still produces a verifiable response (TOCTOU)",
    (await pki.ocsp.verify(racedSigned, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: new Date() })).status === "good");

  // The same window one level in, for the composite key shape. A composite whose components
  // are both PEM strings holds nothing mutable INSIDE it, but the descriptor object is still
  // the caller's: reassigning a component after the call reaches the deferred signing step and
  // yields a response whose responder ID and embedded certificate describe one responder over
  // a signature made by another key. The container is cloned regardless of component type, so
  // a post-call reassignment must not change what signed.
  // The discriminator is an INVALID replacement: if the descriptor leaked, the deferred sign
  // reads the corrupted component and throws; if it was cloned, signing completes on the key
  // that was actually passed. That distinguishes the two without needing a verify oracle for a
  // synthetic composite responder.
  var signing = require("../helpers/signing");
  var compA = signing.makeCompositeSigner("id-MLDSA44-ECDSA-P256-SHA256", { subject: "Composite Responder" });
  function toPem(der) {
    return "-----BEGIN PRIVATE KEY-----\n" + Buffer.from(der).toString("base64").replace(/(.{64})/g, "$1\n").replace(/\n$/, "") + "\n-----END PRIVATE KEY-----\n";
  }
  var pemComposite = { mldsa: toPem(compA.key.mldsa), trad: toPem(compA.key.trad) };
  var compSignP = pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer,
    status: "good", thisUpdate: recent, nextUpdate: new Date(Date.now() + 7 * 24 * 3600 * 1000) }] },
  { cert: compA.cert, key: pemComposite });
  pemComposite.mldsa = "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n";
  pemComposite.trad = "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n";
  check("an all-PEM composite responder descriptor reassigned after the call still signs with what was passed",
    (await (async function () {
      try { var d = await compSignP; return Buffer.isBuffer(d) && d.length > 0; }
      catch (e) { return "THREW:" + e.code; }
    })()) === true);

  // Closing the aliasing window means COPYING a private key, which is a second copy of a
  // secret -- so the copy is cleared once signing is done rather than left for the collector.
  // Observed through the shipped path: the caller's own key must be untouched (never written
  // to), while a response still signs, so the copy that existed in between is gone.
  var wipeProbeKey = Buffer.from(w.responderKeyPkcs8);
  var beforeSign = Buffer.from(wipeProbeKey);
  var wipeSigned = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer,
    status: "good", thisUpdate: recent, nextUpdate: new Date(Date.now() + 7 * 24 * 3600 * 1000) }] },
  { cert: w.responderCertDer, key: wipeProbeKey });
  check("the caller's own responder key is never written to",
    wipeProbeKey.equals(beforeSign) && Buffer.isBuffer(wipeSigned));
  check("...and the response it signed still verifies",
    (await pki.ocsp.verify(wipeSigned, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: new Date() })).status === "good");

  // The buffer the toolkit ALLOCATES is the one that has to be cleared, and it exists from the
  // entry point onward -- taken before the response list, responder ID, SingleResponses, dates,
  // nonce and signature scheme are validated, every one of which can fail. Watching the caller's
  // own key stay untouched says nothing about that copy, so the clear is observed where the
  // toolkit performs it: each buffer must hold key material when handed over and be all-zero
  // afterwards. The failure chosen here is reached long before any signing, which is the window
  // a cleanup attached to the signing call alone would miss.
  // The observation runs in a child process, because it has to be installed before the toolkit
  // loads: the wipe goes through a fill captured at module load and the guard family freezes its
  // exports, so a test that reached in afterwards would be doing the thing both defenses exist to
  // refuse -- and would pass by doing it. Patching the prototype method first makes the capture the
  // toolkit takes the recording one, which is the only honest seam left and the attacker's own.
  var wipeObs = require("node:child_process").spawnSync(process.execPath,
    [require("node:path").join(__dirname, "../helpers/observe-secret-wipe.js")],
    { encoding: "utf8", input: JSON.stringify({
      op: "ocsp-sign-early-fail",
      cert: Buffer.from(w.responderCertDer).toString("base64"),
      key: Buffer.from(w.responderKeyPkcs8).toString("base64"),
    }) });
  var wipeReport = null;
  if (!wipeObs.error && wipeObs.status === 0) {
    try { wipeReport = JSON.parse(String(wipeObs.stdout).trim().split("\n").pop()); } catch (_e) { wipeReport = null; }
  }
  check("the wipe observation ran (child exit " + wipeObs.status + ")", wipeReport !== null);
  check("a response with no SingleResponse is refused", wipeReport && wipeReport.code === "ocsp/bad-input");
  check("the responder key copy is wiped when the failure comes before signing",
    !!wipeReport && wipeReport.wiped.length > 0 && wipeReport.wiped.some(function (e) { return e.hadContent; }) &&
      wipeReport.wiped.every(function (e) { return e.allZeroAfter; }));

  check("a string certID is refused, never read as its ASCII",
    (await codeOfAsync(function () {
      return pki.ocsp.sign({ responderID: "byName", responses: [{ certID: "3081", status: "good", thisUpdate: recent, nextUpdate: new Date(Date.now() + 7 * 24 * 3600 * 1000) }] },
        { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
    })) === "ocsp/bad-input");
  // revoked with a NUMERIC reason code.
  var revNum = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: { revoked: new Date("2027-03-01Z"), revocationReason: 1 }, thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("revoked with a numeric revocationReason surfaces it", (await verify(w, revNum)).revocationReason === "keyCompromise");
  // revoked with NO reason (revocationReason omitted).
  var revNoReason = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: { revoked: new Date("2027-03-01Z") }, thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("revoked with no revocationReason still verifies revoked", (await verify(w, revNoReason)).status === "revoked");
  check("revoked with an unknown revocationReason name -> ocsp/bad-input",
    (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: { revoked: new Date(), revocationReason: "notARealReason" }, thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  // requestNonce given as a non-Buffer -> never matches (fails closed, not a throw).
  check("a non-Buffer requestNonce never matches -> unknown", (await verify(w, goodN, { requestNonce: "not-a-buffer" })).status === "unknown");

  // ---- singleRequestExtensions (full profile) + the lightweight-profile reject ----
  var singleExt = b.sequence([b.oid("1.3.6.1.4.1.99999.2"), b.octetString(b.nullValue())]);
  var reqSingle = await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer, singleRequestExtensions: [singleExt] });
  check("a query singleRequestExtension round-trips into the Request", pki.schema.ocsp.parseRequest(reqSingle).requestList[0].singleRequestExtensions.length === 1);
  check("the lightweight profile forbids singleRequestExtensions",
    (await codeOfAsync(function () { return pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer, singleRequestExtensions: [singleExt] }, { profile: "lightweight" }); })) === "ocsp/bad-input");

  // ---- sign option defaults + verify input/opts arms ----
  var ridDefault = await pki.ocsp.sign({ responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("responderID omitted defaults to byName + verifies good", (await verify(w, ridDefault)).status === "good");
  check("sign with responseData carrying no responses -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName" }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  check("sign with a null response entry -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [null] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");
  var withProduced = await pki.ocsp.sign({ responderID: "byName", producedAt: new Date("2027-05-01Z"), extendedRevoke: true, responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("explicit producedAt + extendedRevoke build + verify good", (await verify(w, withProduced)).status === "good");
  check("verify with no opts -> ocsp/bad-input (cert + issuer required)", (await codeOfAsync(function () { return pki.ocsp.verify(good); })) === "ocsp/bad-input");
  check("verify accepts the parser's own response object", (await pki.ocsp.verify(pki.schema.ocsp.parseResponse(good), { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T })).status === "good");
  // ...and refuses a REBUILT one. The signature, the algorithm that verifies it and the bytes it
  // covers are three separate properties, so a copy is where they can stop belonging together --
  // and Object.assign / spread, which copy own enumerable properties, are how such a copy is made.
  check("verify refuses an Object.assign copy of it",
    (await codeOfAsync(function () { return pki.ocsp.verify(Object.assign({}, pki.schema.ocsp.parseResponse(good)), { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T }); })) === "ocsp/bad-input");
  // A mark that only said "this came from the parser" would survive both of these, which is why the
  // record carries the BYTES and the verdict is re-derived from them: editing the object in place
  // leaves any flag intact while the three parts describe something else, and Object.create
  // inherits every symbol through the prototype chain while letting each field be shadowed.
  var mutatedResp = pki.schema.ocsp.parseResponse(good);
  mutatedResp.basicResponse.signature = { bytes: Buffer.alloc(64, 7), unusedBits: 0 };
  check("editing a parsed response in place does not change the verdict: it is re-derived",
    (await pki.ocsp.verify(mutatedResp, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T })).status === "good");
  var shadowedResp = Object.create(pki.schema.ocsp.parseResponse(good));
  shadowedResp.basicResponse = { tbsResponseDataBytes: Buffer.alloc(4), signatureAlgorithm: { oid: "1.2" }, signature: { bytes: Buffer.alloc(4), unusedBits: 0 }, responses: [], certs: [] };
  check("an Object.create shadow does not inherit provenance it did not earn",
    (await codeOfAsync(function () { return pki.ocsp.verify(shadowedResp, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T }); })) === "ocsp/bad-input");
  // Any property, however hidden, is READ through the object -- and every read of an object is
  // interceptable. A Proxy is handed whatever key a trap is asked about, so it can answer for a
  // symbol it was never told, claim any provenance and name any bytes. The record is therefore kept
  // off the object entirely, and the lookup is on identity: a Proxy is a different object.
  var realResp = pki.schema.ocsp.parseResponse(good);
  var forged = new Proxy(realResp, {
    getOwnPropertyDescriptor: function () { return { value: { kind: "ocspResponse", source: Buffer.alloc(4) }, configurable: true, enumerable: false }; },
    get: function (t, k) { return k === "basicResponse" ? undefined : Reflect.get(t, k); },
  });
  check("a Proxy cannot answer for provenance it does not have",
    (await codeOfAsync(function () { return pki.ocsp.verify(forged, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T }); })) === "ocsp/bad-input");
  // ...including one whose target INHERITS from a real parse result, which is how an own-property
  // rule would have been defeated: the trap is asked about the key and answers whatever it likes.
  var inheritForged = new Proxy(Object.create(realResp), {
    getOwnPropertyDescriptor: function (t, k) { return Reflect.getOwnPropertyDescriptor(t, k) || { value: 1, configurable: true, enumerable: false }; },
    get: function (t, k) { return Reflect.get(t, k); },
  });
  check("...and one inheriting from a real parse result is refused too",
    (await codeOfAsync(function () { return pki.ocsp.verify(inheritForged, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T }); })) === "ocsp/bad-input");
  // The snapshot is taken BEFORE the parse and the parser is given the snapshot, so a typed-array
  // whose byteOffset/byteLength change between reads cannot show one thing to the parser and
  // another to the record -- there is only one read.
  var shifty = new Uint8Array(good);
  Object.defineProperty(shifty, "byteLength", { get: (function () { var n = 0; return function () { return (n++ === 0) ? good.length : 4; }; })() });
  var fromShifty = pki.schema.ocsp.parseResponse(shifty);
  check("a typed array with stateful length getters cannot split the parse from the record",
    (await pki.ocsp.verify(fromShifty, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T })).status === "good");
  // pki.ocsp.verify reads the nonce off the response it parsed and the signature is checked by the
  // path verb. ONE snapshot has to serve both: taking a second from the caller's argument lets a
  // shared-memory view differ between them, so the nonce compared would belong to one response and
  // the signature verified to another. The same bytes going in twice must give one verdict.
  var mutating = new Uint8Array(Buffer.from(good));
  var vFirst = await pki.ocsp.verify(mutating, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T });
  mutating.fill(0);
  check("the verdict describes the bytes read at entry, not the buffer afterwards",
    vFirst.status === "good" &&
    (await pki.ocsp.verify(pki.schema.ocsp.parseResponse(Buffer.from(good)), { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T })).status === "good");
  // ...and the recorded bytes are a COPY, so overwriting the caller's own Buffer after parsing
  // cannot change what the verdict is computed over.
  var mutableDer = Buffer.from(good);
  var fromMutable = pki.schema.ocsp.parseResponse(mutableDer);
  mutableDer.fill(0);
  check("overwriting the caller's buffer after parsing does not change the verdict",
    (await pki.ocsp.verify(fromMutable, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T })).status === "good");
  check("verify accepts already-parsed cert + issuer objects", (await pki.ocsp.verify(good, { cert: pki.schema.x509.parse(w.targetCertDer), issuer: pki.schema.x509.parse(w.issuerCertDer), time: T })).status === "good");
  check("verify defaults opts.time to now when omitted", (await pki.ocsp.verify(bareGood, { cert: w.targetCertDer, issuer: w.issuerCertDer })).status === "good");
  var unkNonce = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.altCaCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }, { nonce: Buffer.alloc(32, 5) });
  check("a nonce mismatch on an already-unknown verdict stays unknown", (await verify(w, unkNonce, { requestNonce: Buffer.alloc(32, 6) })).status === "unknown");

  // ---- the lower-level pki.path.verifyOcspResponse primitive pki.ocsp.verify composes ----
  var lowGood = await pki.path.verifyOcspResponse(good, pki.schema.x509.parse(w.targetCertDer), pki.schema.x509.parse(w.issuerCertDer), T);
  check("pki.path.verifyOcspResponse (response DER) -> good, authorized, matched", lowGood.status === "good" && lowGood.responderAuthorized === true && lowGood.matched === true);
  // #68: the OCSP response accepts any BufferSource, not only a Buffer / Uint8Array / PEM. An ArrayBuffer
  // of the same DER verifies identically; before the widening it was refused as path/bad-input.
  var _goodAB = new ArrayBuffer(good.length); new Uint8Array(_goodAB).set(good);
  var lowGoodAB = await pki.path.verifyOcspResponse(_goodAB, pki.schema.x509.parse(w.targetCertDer), pki.schema.x509.parse(w.issuerCertDer), T);
  check("pki.path.verifyOcspResponse accepts an ArrayBuffer response DER (#68)", lowGoodAB.status === "good" && lowGoodAB.matched === true);
  var lowStale = await pki.path.verifyOcspResponse(noNext, pki.schema.x509.parse(w.targetCertDer), pki.schema.x509.parse(w.issuerCertDer), T);
  check("pki.path.verifyOcspResponse fail-closes an uncacheable (no nextUpdate) response to unknown", lowStale.status === "unknown");
  // A signature check has three parts -- the signature, the algorithm that verifies it, and the
  // bytes it covers -- and a parsed response carries all three as separate properties. Pair a real
  // CA signature over a certificate that CA ISSUED with that certificate's own tbsBytes and
  // algorithm, relabel the three, and every part of the check passes for a response that never
  // existed. The verb takes bytes, so the three cannot be assembled from different sources.
  var targetParsed = pki.schema.x509.parse(w.targetCertDer);
  var replay = {
    responseStatus: { code: 0 },
    basicResponse: {
      tbsResponseDataBytes: targetParsed.tbsBytes,
      signatureAlgorithm: targetParsed.signatureAlgorithm,
      signature: targetParsed.signatureValue,
      certs: [], responderID: { byName: pki.schema.x509.parse(w.issuerCertDer).subject }, responses: [],
    },
  };
  check("a parsed response is refused, so a certificate's own signature cannot be replayed as one",
    (await codeOfAsync(function () { return pki.path.verifyOcspResponse(replay, targetParsed, pki.schema.x509.parse(w.issuerCertDer), T); })) === "path/bad-input");
  check("pki.ocsp.verify refuses it at its own door too",
    (await codeOfAsync(function () { return pki.ocsp.verify(replay, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T }); })) === "ocsp/bad-input");

  // ---- dispatch + config-time ----
  check("pki.schema.parse routes a signed response to the OCSP-response parser", (function () { var r = pki.schema.parse(good); return r.responseStatus && r.responseStatus.code === 0; })());
  check("verify without opts.cert/issuer -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.verify(good, {}); })) === "ocsp/bad-input");
  // A NaN opts.time must fail closed, not silently disable the currency + delegate-validity windows.
  check("verify rejects an invalid opts.time (NaN Date) -> ocsp/bad-input",
    (await codeOfAsync(function () { return pki.ocsp.verify(good, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: new Date("not a date") }); })) === "ocsp/bad-input");
  check("verify rejects an unparseable opts.time string -> ocsp/bad-input",
    (await codeOfAsync(function () { return pki.ocsp.verify(good, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: "not a date" }); })) === "ocsp/bad-input");
  check("pki.path.verifyOcspResponse rejects an invalid time -> path/bad-input",
    (await codeOfAsync(function () { return pki.path.verifyOcspResponse(good, pki.schema.x509.parse(w.targetCertDer), pki.schema.x509.parse(w.issuerCertDer), new Date("not a date")); })) === "path/bad-input");
  check("sign without a responder key -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ certID: Buffer.alloc(4), status: "good" }] }, { cert: w.responderCertDer }); })) === "ocsp/bad-input");
  check("sign with no responses -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");

  // ---- an option this module does not read is refused, not ignored ----
  // Each of the three verbs carries a nonce option, and each means something different:
  // buildRequest SENDS one, sign ECHOES one, verify BINDS against the one that was sent. A
  // misspelling on any of them leaves the anti-replay binding absent while the call site reads
  // as though it were present.
  check("buildRequest refuses a misspelled nonce",
    await codeOfAsync(function () {
      return pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer }, { nonces: true });
    }) === "ocsp/bad-input");
  check("buildRequest still accepts every option its @opts block documents",
    Buffer.isBuffer(await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer },
      { hashAlgorithm: "sha256", nonce: true })));
  check("sign refuses a misspelled nonce",
    await codeOfAsync(function () {
      return pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good" }] },
        { cert: w.issuerCertDer, key: w.issuerKey }, { noncce: Buffer.alloc(4, 1) });
    }) === "ocsp/bad-input");
  check("verify refuses a misspelled requestNonce",
    await codeOfAsync(function () {
      return pki.ocsp.verify(Buffer.alloc(2), { cert: w.targetCertDer, issuer: w.issuerCertDer, requestNonces: Buffer.alloc(4) });
    }) === "ocsp/bad-input");
  check("verify's refusal names the option that binds the response",
    await (async function () {
      try {
        await pki.ocsp.verify(Buffer.alloc(2), { cert: w.targetCertDer, issuer: w.issuerCertDer, requestNonces: Buffer.alloc(4) });
        return false;
      } catch (e) { return /requestNonce/.test(e.message); }
    })());

  // buildRequest and sign take their arguments through guard.bytes.fixedCall, whose snapshot
  // copies every readable name onto a fresh object. A method the caller's class defines therefore
  // arrives as an own property, and the check has to hold anyway: it recognizes a method by the
  // identical function on the chain above, which reads the same before and after the copy.
  function RequestBag() { this.hashAlgorithm = "sha256"; }
  RequestBag.prototype.describe = function () { return "request"; };
  check("buildRequest accepts an options instance whose class defines a method",
    Buffer.isBuffer(await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer },
      new RequestBag())));
  function ResponseBag() { this.embedCert = true; }
  ResponseBag.prototype.describe = function () { return "response"; };
  check("sign accepts an options instance whose class defines a method",
    Buffer.isBuffer(await pki.ocsp.sign(
      { responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "good" }] },
      { cert: w.issuerCertDer, key: w.issuerKeyPkcs8 }, new ResponseBag())));

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
