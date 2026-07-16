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
  var rev = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: { revoked: new Date("2027-03-01Z"), revocationReason: "keyCompromise" }, thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  var vr = await verify(w, rev);
  check("verify revoked surfaces the status + reason", vr.status === "revoked" && vr.revocationReason === "keyCompromise");
  var unk = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.issuerCertDer, status: "unknown", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("verify explicit unknown status", (await verify(w, unk)).status === "unknown");
  // raw-exactness: mutate one byte of the signed response -> signature no longer verifies.
  var tampered = Buffer.from(good); tampered[tampered.length - 40] ^= 0x01;
  var vt = await verify(w, tampered);
  check("a mutated response byte -> signatureValid:false, status unknown", vt.status === "unknown" && vt.signatureValid === false);

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

  // ---- buildErrorResponse ----
  var err = pki.ocsp.buildErrorResponse("tryLater");
  var pe = pki.schema.ocsp.parseResponse(err);
  check("buildErrorResponse('tryLater') -> status tryLater, no basicResponse (RFC 6960 sec. 2.3)",
    pe.responseStatus.name === "tryLater" && pe.basicResponse === null);
  check("buildErrorResponse rejects an unknown status", codeOf(function () { pki.ocsp.buildErrorResponse("bogus"); }) === "ocsp/bad-input");

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
    (function (r) { return r.status === "unknown" && r.signatureValid === false; })(await pki.path.verifyOcspResponse(pki.schema.ocsp.parseResponse(rogueResp), pki.schema.x509.parse(w.targetCertDer), pki.schema.x509.parse(w.rogueIssuerCertDer), T)));
  check("an issuer whose subject DN differs from the target's issuer is rejected (name binding)",
    (await verify(w, good, { cert: w.targetCertDer, issuer: w.altCaCertDer })).status === "unknown");

  // ---- CertID mismatch (cross-CA substitution defense) ----
  var wrongCertId = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.altCaCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 });
  check("CertID mismatch: issuerKeyHash of a different CA -> not-about-this-cert, unknown", (await verify(w, wrongCertId)).status === "unknown");

  // ---- signed request (optionalSignature) + requestorName forms ----
  var signedReq = await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer },
    { requestorName: nameDN("Requestor"), signer: { cert: w.responderCertDer, key: w.responderKeyPkcs8 } });
  var psr = pki.schema.ocsp.parseRequest(signedReq);
  check("a signed request carries requestorName + optionalSignature", psr.requestorName != null && psr.optionalSignature != null);
  var signedReq2 = await pki.ocsp.buildRequest({ cert: w.targetCertDer, issuer: w.issuerCertDer },
    { requestorName: { bytes: nameDN("Parsed Requestor") }, signer: { cert: pemCert(w.responderCertDer), key: w.responderKeyPkcs8 } });
  check("requestorName accepts a parsed Name ({bytes}) and the signer cert accepts PEM", pki.schema.ocsp.parseRequest(signedReq2).requestorName != null);
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
  check("verify accepts an already-parsed response object", (await pki.ocsp.verify(pki.schema.ocsp.parseResponse(good), { cert: w.targetCertDer, issuer: w.issuerCertDer, time: T })).status === "good");
  check("verify accepts already-parsed cert + issuer objects", (await pki.ocsp.verify(good, { cert: pki.schema.x509.parse(w.targetCertDer), issuer: pki.schema.x509.parse(w.issuerCertDer), time: T })).status === "good");
  check("verify defaults opts.time to now when omitted", (await pki.ocsp.verify(bareGood, { cert: w.targetCertDer, issuer: w.issuerCertDer })).status === "good");
  var unkNonce = await pki.ocsp.sign({ responderID: "byName", responses: [{ cert: w.targetCertDer, issuer: w.altCaCertDer, status: "good", thisUpdate: TU, nextUpdate: NU }] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }, { nonce: Buffer.alloc(32, 5) });
  check("a nonce mismatch on an already-unknown verdict stays unknown", (await verify(w, unkNonce, { requestNonce: Buffer.alloc(32, 6) })).status === "unknown");

  // ---- the lower-level pki.path.verifyOcspResponse primitive pki.ocsp.verify composes ----
  var parsedGood = pki.schema.ocsp.parseResponse(good);
  var lowGood = await pki.path.verifyOcspResponse(parsedGood, pki.schema.x509.parse(w.targetCertDer), pki.schema.x509.parse(w.issuerCertDer), T);
  check("pki.path.verifyOcspResponse (parsed inputs) -> good, authorized, matched", lowGood.status === "good" && lowGood.responderAuthorized === true && lowGood.matched === true);
  var parsedNoNext = pki.schema.ocsp.parseResponse(noNext);
  var lowStale = await pki.path.verifyOcspResponse(parsedNoNext, pki.schema.x509.parse(w.targetCertDer), pki.schema.x509.parse(w.issuerCertDer), T);
  check("pki.path.verifyOcspResponse fail-closes an uncacheable (no nextUpdate) response to unknown", lowStale.status === "unknown");

  // ---- dispatch + config-time ----
  check("pki.schema.parse routes a signed response to the OCSP-response parser", (function () { var r = pki.schema.parse(good); return r.responseStatus && r.responseStatus.code === 0; })());
  check("verify without opts.cert/issuer -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.verify(good, {}); })) === "ocsp/bad-input");
  // A NaN opts.time must fail closed, not silently disable the currency + delegate-validity windows.
  check("verify rejects an invalid opts.time (NaN Date) -> ocsp/bad-input",
    (await codeOfAsync(function () { return pki.ocsp.verify(good, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: new Date("not a date") }); })) === "ocsp/bad-input");
  check("verify rejects an unparseable opts.time string -> ocsp/bad-input",
    (await codeOfAsync(function () { return pki.ocsp.verify(good, { cert: w.targetCertDer, issuer: w.issuerCertDer, time: "not a date" }); })) === "ocsp/bad-input");
  check("pki.path.verifyOcspResponse rejects an invalid time -> path/bad-input",
    (await codeOfAsync(function () { return pki.path.verifyOcspResponse(pki.schema.ocsp.parseResponse(good), pki.schema.x509.parse(w.targetCertDer), pki.schema.x509.parse(w.issuerCertDer), new Date("not a date")); })) === "path/bad-input");
  check("sign without a responder key -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [{ certID: Buffer.alloc(4), status: "good" }] }, { cert: w.responderCertDer }); })) === "ocsp/bad-input");
  check("sign with no responses -> ocsp/bad-input", (await codeOfAsync(function () { return pki.ocsp.sign({ responderID: "byName", responses: [] }, { cert: w.responderCertDer, key: w.responderKeyPkcs8 }); })) === "ocsp/bad-input");

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
