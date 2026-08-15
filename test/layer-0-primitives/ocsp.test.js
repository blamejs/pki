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
  // The field is three-state and always present: true bound, false not bound, null never asked.
  // Absent would make "not requested" indistinguishable from "this build does not report it".
  check("a client that sent no nonce still gets nonceMatched, as null",
    (function (r) { return "nonceMatched" in r && r.nonceMatched === null; })(await verify(w, goodN)));
  check("a client that sent a nonce gets a boolean, not null",
    (await verify(w, goodN, { requestNonce: Buffer.alloc(32, 7) })).nonceMatched === true);
  // The downgrade is for `good` ONLY. A revoked verdict does not expire the way a
  // non-revocation does, so discarding a signed, current, authorized `revoked`
  // because it was replayed would hand a soft-fail caller the very certificate the
  // responder refused -- the anti-replay defence becoming the thing that accepts it.
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
  var guardAll = require("../../lib/guard-all");
  var realZeroizeAll = guardAll.secret.zeroizeAll;
  var wiped = [];
  guardAll.secret.zeroizeAll = function (list) {
    var seen = (list || []).filter(Boolean).map(function (bufr) {
      return { buf: bufr, hadContent: bufr.some(function (x) { return x !== 0; }) };
    });
    var out = realZeroizeAll.apply(this, arguments);
    wiped.push.apply(wiped, seen);
    return out;
  };
  var earlyFailCode;
  try {
    earlyFailCode = await codeOfAsync(function () {
      return pki.ocsp.sign({ responderID: "byName", responses: [] },
        { cert: w.responderCertDer, key: Buffer.from(w.responderKeyPkcs8) });
    });
  } finally { guardAll.secret.zeroizeAll = realZeroizeAll; }
  check("a response with no SingleResponse is refused", earlyFailCode === "ocsp/bad-input");
  check("the responder key copy is wiped when the failure comes before signing",
    wiped.length > 0 && wiped.every(function (e) {
      return e.hadContent && e.buf.every(function (x) { return x === 0; });
    }));

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

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
