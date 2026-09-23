// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var net = require("net");
var asn1 = require("./asn1-der");
var constants = require("./constants");
var oid = require("./oid");
var guard = require("./guard-all");
var intrinsic = require("./guard-intrinsic");
var frameworkError = require("./framework-error");
var pkix = require("./schema-pkix");
var ocsp = require("./ocsp");
var crlSchema = require("./schema-crl");
var crlVerify = require("./crl-verify");
var httpTransport = require("./http-transport");
var mime = require("./mime");
var pathValidate = require("./path-validate");
var ocspSchema = require("./schema-ocsp");

var PathError = frameworkError.PathError;
function E(code, message, cause) { return new PathError(code, message, cause); }

var NS = pkix.makeNS("path", PathError, oid);
var EXT_DECODERS = pkix.certExtensionDecoders(NS).byOid;

var OID_CDP = oid.byName("cRLDistributionPoints");
var OID_FRESHEST = oid.byName("freshestCRL");
var OID_AIA = oid.byName("authorityInfoAccess");
var OID_AD_OCSP = oid.byName("ocsp");
var OID_OCSP_NONCE = oid.byName("ocspNonce");

var _append = guard.list.append;
var LIMITS = constants.LIMITS;

var CHECKER_OPTS = intrinsic.assign(intrinsic.create(null), {
  transport: 1, allowPlaintextHttp: 1, useDeltas: 1, nonce: 1, tls: 1,
  maxFetches: 1, maxPerCert: 1, maxResponseBytes: 1, totalDeadlineMs: 1,
  sourceTimeoutMs: 1, retries: 1, toleranceMs: 1, cache: 1,
});

/** @internal A candidate is `{ kind, url, reasons }`, where `kind` says which parser the body goes
 * to. The structure is decided by where the URL came from and never by what came back, so a
 * Content-Type header cannot choose a parser. */
var KIND_CRL = "crl";
var KIND_OCSP = "ocsp";

var TRANSPORT_SHAPE = "(request) => Promise<{ status, headers, body }>";

/** @internal An extension the certificate may not carry, and may carry malformed. A decode fault is
 * a reason rather than a throw, because this runs inside a checker whose every outcome is a
 * verdict (RFC 5280 sec. 6.3.3 closing paragraph: an undetermined status, never an unrevoked one). */
/** @internal An extension that does not decode names no URL, which is not the same as naming none:
 * a certificate carrying an unreadable cRLDistributionPoints has a revocation location an operator
 * cannot reach, and one carrying no such extension has none to reach. Both end at an undetermined
 * status, so the difference lives in the reason, and the refusal is recorded as a skip rather than
 * swallowed. */
function _softDecode(holder, extOid, skips) {
  var list = holder.extensions || holder.crlExtensions || [];
  var found = guard.list.anyMatches(list, function (e) { return !!e && e.oid === extOid; })
    ? _firstWithOid(list, extOid) : null;
  if (found === null) return null;
  try { return EXT_DECODERS[extOid](found.value); }
  catch (e) {
    if (skips) _append(skips, "the " + (oid.name(extOid) || extOid) + " extension does not decode: " + _say(e));
    return null;
  }
}

function _firstWithOid(list, extOid) {
  for (var i = 0; i < list.length; i++) {
    if (list[i] && list[i].oid === extOid) return list[i];
  }
  return null;
}

/** @internal RFC 5280 sec. 4.2.1.13 classification, on the DER shape and never on a string. A
 * distribution point is fetchable over HTTP only as a `fullName` carrying a `uniformResourceIdentifier`
 * whose scheme this client speaks. Everything else is a skip with its reason named, which is what
 * keeps "no fetchable distribution point" distinct from "the fetch failed". */
function _crlCandidates(points, net_, skips) {
  var out = [];
  if (!intrinsic.isArray(points)) return out;
  for (var i = 0; i < points.length; i++) {
    var dp = points[i];
    if (!dp.distributionPoint) {
      _append(skips, dp.cRLIssuer ? "a distribution point names a cRLIssuer and no location" :
        "a distribution point names no location");
      continue;
    }
    if (dp.distributionPoint.kind !== "fullName") {
      _append(skips, "a distribution point uses nameRelativeToCRLIssuer, which names no location");
      continue;
    }
    var names = dp.distributionPoint.names || [];
    var tookOne = false;
    for (var n = 0; n < names.length; n++) {
      var gn = _generalName(names[n]);
      if (gn === null || gn.tag !== 6) { _append(skips, "a distribution point name is not a URI"); continue; }
      var got = _acceptableUrl(gn.value, net_);
      if (got.url === null) { _append(skips, "a distribution point URI " + got.why + ": " + guard.text.showValue(gn.value)); continue; }
      _append(out, { kind: KIND_CRL, url: got.url, reasons: dp.reasons || null });
      tookOne = true;
    }
    if (!tookOne && names.length === 0) _append(skips, "a distribution point carries an empty fullName");
  }
  return out;
}

/** @internal The decoded fullName entry is the GeneralName bytes; the decoder surfaces the value
 * when it was asked to decode one, and the raw bytes when it was not. Both shapes are read here so
 * the caller of this module does not have to know which drive the extension took. */
function _generalName(entry) {
  if (!entry) return null;
  if (typeof entry === "object" && typeof entry.tag === "number") return { tag: entry.tag, value: entry.value };
  if (typeof entry === "object" && typeof entry.tagNumber === "number") return { tag: entry.tagNumber, value: entry.value };
  if (guard.bytes.isByteSource(entry)) {
    /** @internal The fullName entries arrive as the GeneralName's own DER, so the tag and the
     * content come from the codec. Reading the length by hand would be right only while every URI
     * stayed under 128 bytes. */
    var node;
    try { node = asn1.decode(guard.bytes.source(entry, PathError, "path/bad-input", "a distribution point name")); }
    catch (_e) { return null; }     // allow:swallow-unverified a name that does not decode names no location
    if (node.tagClass !== "context") return null;
    return { tag: node.tagNumber, value: intrinsic.bufToString(node.content, "latin1") };
  }
  return null;
}

/** @internal RFC 5280 sec. 4.2.2.1 puts the responder at an AccessDescription whose accessMethod is
 * id-ad-ocsp and whose accessLocation is a URI. No CRL URL is ever taken from this extension, which
 * that section states outright. */
function _ocspCandidates(descriptions, net_, skips) {
  var out = [];
  if (!intrinsic.isArray(descriptions)) return out;
  for (var i = 0; i < descriptions.length; i++) {
    var ad = descriptions[i];
    if (ad.accessMethod !== OID_AD_OCSP) continue;
    if (!ad.accessLocation || ad.accessLocation.tag !== 6) {
      _append(skips, "an id-ad-ocsp access location is not a URI (RFC 5280 sec. 4.2.2.1)");
      continue;
    }
    var got = _acceptableUrl(ad.accessLocation.value, net_);
    if (got.url === null) { _append(skips, "an id-ad-ocsp URI " + got.why + ": " + guard.text.showValue(ad.accessLocation.value)); continue; }
    _append(out, { kind: KIND_OCSP, url: got.url, reasons: null });
  }
  return out;
}

/** @internal The URL this client will open, with the clause naming why it will not when it will
 * not. The scheme decides first, then the SSRF rules the AIA route already applies: no private,
 * loopback or link-local destination, and a hostname only where the transport filters the address
 * it resolved. The fragment is dropped, since it is never sent.
 *
 * An address literal is decided here, because the destination is in the URL. A name is not: what
 * it resolves to is decided inside whoever opens the socket, so a certificate naming
 * `crl.internal.example` reaches a private network unless that resolution is filtered and pinned.
 * The transport `pki.transport.https(defaults)` returns declares `blocksPrivateAddresses` and does
 * both; a transport that declares nothing is never handed a name. The declaration is read off the
 * transport's own slot, because `Function.prototype` carries whatever has been written to it for
 * every function in the process. */
function _acceptableUrl(value, net_) {
  if (typeof value !== "string" || value === "") return _no("is not one this client fetches");
  var u;
  try { u = new URL(value); }
  catch (_e) { return _no("is not one this client fetches"); }   // allow:swallow-unverified a value that is not a URL names no location
  if (u.protocol !== "https:" && !(net_.allowHttp && u.protocol === "http:")) return _no("is not one this client fetches");
  var host = u.hostname;
  if (host.charAt(0) === "[" && host.charAt(host.length - 1) === "]") host = host.slice(1, -1);
  if (net.isIP(host) !== 0) {
    if (httpTransport.isBlockedIp(host)) return _no("is not one this client fetches");
  } else if (!net_.guardsAddresses) {
    return _no("names a host whose resolved address opts.transport does not declare it filters");
  }
  u.hash = "";
  return { url: u.href, why: null };
}

function _no(why) { return { url: null, why: why }; }

/** @internal Whether this transport says it filters the address it resolved. A transport is a
 * function, so the flag is asked of the slot rather than of the chain: reading it through the
 * transport finds a value on `Function.prototype`, which every function in the process carries and
 * which nobody who wrote a transport declared. What the flag buys is a hostname destination taken
 * from a certificate, so an undeclared transport being read as declaring it is the whole guard.
 * @guard-via guard.identifier.declaresOwn */
function _declaresAddressGuard(transport) {
  return guard.identifier.declaresOwn(transport, "blocksPrivateAddresses");
}

/** @internal Reuse is decided from the signed window and from nothing else: RFC 5019 sec. 7.5 has a
 * client rely on the values in the signed response, and sec. 6.1 admits only a response whose
 * signature validated. The HTTP caching headers are not read here at all, so they can neither
 * extend an entry's life nor end it.
 *
 * Two key shapes, kept apart on purpose. An OCSP entry is keyed on the CertID tuple and the
 * responder URL it was asked of; a CRL entry on the request URL and the encoded issuer name of the
 * CRL that came back. Neither is the URL the socket was opened on, and neither is the encoded name
 * the sec. 6.3.3(b) distribution point match reads, so a cache hit can never stand in for a name
 * match. */
function _makeCache(maxEntries, maxBytes) {
  var entries = new Map();
  var bytes = 0;
  function evictOldest() {
    var it = entries.keys().next();
    if (it.done) return;
    var old = entries.get(it.value);
    bytes -= old ? old.size : 0;
    entries.delete(it.value);
  }
  return {
    get: function (key, at) {
      var e = entries.get(key);
      if (!e) return null;
      if (!(at < e.notAfter) || !(at >= e.notBefore)) { bytes -= e.size; entries.delete(key); return null; }
      return e.value;
    },
    put: function (key, value, notBefore, notAfter, size) {
      if (!(notAfter instanceof Date) || !(notBefore instanceof Date)) return;
      if (size > maxBytes) return;
      if (entries.has(key)) { bytes -= entries.get(key).size; entries.delete(key); }
      while (entries.size >= maxEntries || bytes + size > maxBytes) {
        if (entries.size === 0) return;
        evictOldest();
      }
      entries.set(key, { value: value, notBefore: notBefore, notAfter: notAfter, size: size });
      bytes += size;
    },
    size: function () { return entries.size; },
    bytes: function () { return bytes; },
  };
}

function _ocspCacheKey(certId, url) {
  return "ocsp|" + url + "|" + certId.hashAlgorithm.oid + "|" +
    intrinsic.bufToString(certId.issuerNameHash, "hex") + "|" +
    intrinsic.bufToString(certId.issuerKeyHash, "hex") + "|" + certId.serialNumberHex;
}

/** @internal What identifies a kept list: the URL it came from, the issuer name it is about, and
 * the key that has to verify it. A CA that rotates its key keeps both its name and its CRL URL,
 * so neither tells the old list from the new one; an entry found on those two alone would be
 * handed to a certificate under the new key, fail its signature check, and leave the status
 * undetermined with no request made until the entry aged out. */
function _crlCacheKey(url, issuerBytes, keyBytes) {
  return "crl|" + url + "|" + intrinsic.bufToString(issuerBytes, "hex") +
    "|" + intrinsic.bufToString(guard.bytes.source(keyBytes, PathError, "path/bad-input", "the issuer public key"), "hex");
}

/** @internal One request. A non-200 is a refusal and no redirect is followed, which matches the AIA
 * route: a 3xx would move the fetch to a location the certificate never named. The body is held to
 * the response cap before anything parses it. */
async function _fetchOne(state, req, what) {
  if (state.deadline.expired()) throw E("path/revocation-fetch-failed", "the revocation deadline passed before " + what);
  state.fetches.tick();
  var timeout = state.sourceTimeoutMs;
  var left = state.deadline.remaining();
  if (left < timeout) timeout = left;
  /** @internal The `timeout` field asks the transport to stop; the bound here makes it stop. A
   * transport is caller code and need not implement the field, and one that never settles would
   * otherwise hold the validation open with no deadline reached, since the deadline is only read
   * between requests. The bound is whatever the deadline has left, so the totals an operator set
   * hold whatever the transport does. */
  var res = await guard.async.bounded(
    guard.async.invoked(state.transport,
      [{ method: req.method, url: req.url, headers: req.headers, body: req.body, tls: state.tls,
        timeout: timeout, maxResponseBytes: state.maxResponseBytes, blockPrivateAddresses: true,
        allowPlaintextHttp: state.allowPlaintextHttp }],
      E, "path/bad-input", "opts.transport"),
    timeout, E, "path/revocation-fetch-failed", what);
  res = res || {};
  if (res.status !== 200) {
    throw E("path/revocation-fetch-failed", what + " returned HTTP " + res.status + " (only 200 carries a revocation object; no redirect is followed)");
  }
  var body = guard.bytes.isByteSource(res.body)
    ? guard.bytes.source(res.body, PathError, "path/revocation-fetch-failed", "the revocation response body")
    : Buffer.from(res.body == null ? "" : String(res.body), "latin1");
  if (body.length === 0) throw E("path/revocation-fetch-failed", what + " returned an empty body");
  if (body.length > state.maxResponseBytes) {
    throw E("path/revocation-fetch-failed", what + " returned " + body.length + " bytes, over the " + state.maxResponseBytes + "-byte cap");
  }
  return { body: body, contentType: _contentType(res.headers) };
}

function _contentType(headers) {
  var h = headers || {};
  var keys = Object.keys(h);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() !== "content-type") continue;
    try { return mime.parse(String(h[keys[i]])).type; }
    catch (_e) { return null; }     // allow:swallow-unverified an unreadable media type is reported as absent, and it never selects a parser
  }
  return null;
}

/** @internal One responder. The request is the RFC 5019 lightweight profile, so one Request, SHA-1
 * CertID hashes and no singleRequestExtensions, and the HTTP shape is decided by sec. 5. The
 * verdict is `pathValidate.verifyOcspResponse`, which is the single acceptance gate: the CertID
 * match, the responder authorization including the delegate path, the signature and the currency
 * all live there, and none of them is restated here. */
async function _tryOcsp(state, cert, issuer, ctx, candidate) {
  var issuerCert = issuer.issuerCert;
  if (!issuerCert) throw E("path/revocation-fetch-failed", "an OCSP request needs the issuer certificate, which this path does not carry");
  var der = await ocsp.buildRequest({ cert: cert.bytes || cert, issuer: issuerCert.bytes || issuerCert },
    { profile: "lightweight", nonce: state.nonce });
  var parsedReq = state.parseRequest(der);
  var certId = parsedReq.requestList[0].certID;
  var key = _ocspCacheKey(certId, candidate.url);
  /** @internal A nonce asks this responder this question now, and every request carries a fresh
   * one, so no response produced before this request can answer it. Reading the cache would hand
   * back the previous response, whose nonce is the previous one, and the check below would refuse
   * it: the cache would turn a working responder into a permanent undetermined. RFC 5019 sec. 6.1
   * caches for the lightweight profile, which sec. 5 defines without a nonce, so the two are
   * alternatives rather than a pair. */
  var hit = state.nonce ? null : state.cache.get(key, ctx.time);
  if (hit === null) {
    var http = ocsp.httpRequest(der, candidate.url);
    var got = await _fetchOne(state, http, "an OCSP request to " + candidate.url);
    if (got.contentType !== null && got.contentType !== "application/ocsp-response") {
      _append(state.notes, "the OCSP response carried content-type " + guard.text.showValue(got.contentType));
    }
    hit = got.body;
  }
  var v = await state.verifyOcspResponse(hit, cert, issuerCert, ctx.time,
    { historicalMode: ctx.historicalMode === true, requestNonce: state.nonce ? _requestNonce(parsedReq) : undefined });
  /** @internal `valid` on that verdict means the certificate is good, not that the response was
   * acceptable, so reading it as acceptance would turn a `revoked` answer into an undetermined
   * one that `opts.softFail` could then waive. Acceptance is the three conditions the gate
   * reports: the CertID matched, the signature verified, and the responder was authorized
   * (RFC 6960 sec. 3.2). The status is then whatever the responder said. */
  var accepted = !!v && v.matched === true && v.signatureValid === true && v.responderAuthorized === true;
  if (!accepted) {
    throw E("path/revocation-fetch-failed", "the OCSP response was not accepted: " + ((v && v.reason) || "no reason given"));
  }
  if (v.status !== "good" && v.status !== "revoked") {
    throw E("path/revocation-fetch-failed", "the OCSP responder answered " + guard.text.showValue(v.status) +
      ((v && v.reason) ? ": " + v.reason : ""));
  }
  /** @internal RFC 5019 sec. 6.1 stores only an authoritative response, and sec. 4 refuses one with
   * no nextUpdate, so the window an entry is reused within always exists by the time this runs. A
   * nonce-bearing response is not stored, since nothing would ever read it back. */
  if (!state.nonce && v.nextUpdate && v.thisUpdate) {
    state.cache.put(key, hit, v.thisUpdate, v.nextUpdate, hit.length);
  }
  return { status: v.status, reason: "an OCSP response from " + candidate.url,
    revocationReason: v.revocationReason, revocationTime: v.revocationTime };
}

/** @internal The bytes the nonce extension carries, which is what the response echoes. The
 * extension's own `value` is those bytes inside their OCTET STRING, so comparing it would never
 * match and the check would report every response as unechoed. */
function _requestNonce(parsedReq) {
  var exts = parsedReq.requestExtensions || [];
  for (var i = 0; i < exts.length; i++) {
    if (exts[i].oid === OID_OCSP_NONCE) return exts[i].nonce || undefined;
  }
  return undefined;
}

/** @internal A cache entry stands in for a fetch for as long as the object's own nextUpdate says,
 * so whatever is admitted is trusted until then and a forged list with a distant nextUpdate would
 * silence the real one for that whole window. Admission is therefore decided about the object being
 * kept: its signature has to verify under the key the path is working with, checked by the same
 * verb `crlChecker` checks it with.
 *
 * The surrounding verdict cannot stand in for that. A base CRL and the delta it names are fetched
 * in one pass and answered together, so a determinate answer there may have come from either, and
 * the forged one would ride in on the genuine one's verdict. Scope and authorization are not
 * decided here, because a cached object is handed back to `crlChecker` on every read and gated
 * again; what the cache has to refuse is an object that is not the issuer's at all. */
function _keep(state, url, parsed, fetchedBytes, keyBytes) {
  if (!(fetchedBytes > 0) || !parsed.nextUpdate || !parsed.thisUpdate) return;
  state.crlCache.put(_crlCacheKey(url, parsed.issuer.bytes, keyBytes), parsed, parsed.thisUpdate, parsed.nextUpdate, fetchedBytes);
}

/** @internal Whether this CRL was signed by the key the path is working with, asked with the verb
 * `crlChecker` asks it with. It answers only that one question: scope, the cRLSign authorization
 * and currency are the checker's, and a CRL that fails any of those is still the issuer's. */
async function _isIssuers(state, parsed, issuer) {
  try { return (await crlVerify.verifyCrlSignature(parsed, issuer.workingPublicKey)) === true; }
  catch (e) {
    _append(state.notes, "a fetched CRL could not be checked against the issuer's key: " + _say(e));
    return false;
  }
}

/** @internal `maxPerCert` bounds the destinations ONE certificate can send this client to, so the
 * set it counts spans every route: a certificate naming five responders and five distribution
 * points chose ten destinations, and counting each route's own list would let it reach twice the
 * figure. A URL already counted is free to be asked again, which is what a retry is. */
function _takeUrl(state, url) {
  if (state.urls.has(url)) return true;
  if (state.urls.size >= state.maxPerCert) return false;
  state.urls.add(url);
  return true;
}

/** @internal Every fetchable distribution point, until the CRLs gathered cover the certificate or
 * the points run out. The acceptance rules are `crlChecker`'s: the issuer match, the cRLSign
 * authorization, the IDP scope, the sec. 6.3.3(b) distribution point correspondence, the currency
 * and the signature. This function decides which bytes to hand it and nothing else. */
async function _tryCrl(state, cert, issuer, ctx, candidates, certDeltas) {
  /** @internal Counted and tried are different. `state.urls` counts the destinations one
   * certificate names, across both routes, against `maxPerCert`; this set records what THIS walk
   * has already asked, so a point named twice is asked once. A certificate naming one URL as its
   * responder and as its distribution point is ordinary, and reading the counted set as the asked
   * set drops the CRL route for it: the responder had counted the URL, so the fallback the OCSP
   * route is documented to have never ran. */
  var gathered = [], asked = new intrinsic.Set();
  for (var i = 0; i < candidates.length; i++) {
    if (state.deadline.expired()) break;
    var url = candidates[i].url;
    if (asked.has(url)) continue;
    if (!_takeUrl(state, url)) break;
    asked.add(url);
    /** @internal A CRL is reused inside the window it signs for, the same rule the responses
     * follow: RFC 5280 sec. 6.3.3(a)(1)(ii) has a replacement checked for currency, so a cached
     * one is kept only while `thisUpdate <= now < nextUpdate`. The key carries the issuer name the
     * CRL itself declared, which is a different string from the URL the socket was opened on and
     * from the encoded name the sec. 6.3.3(b) match reads. */
    /** @internal One unreachable location must not lose the others: RFC 5280 sec. 4.2.1.13 has a
     * certificate name several distribution points so a client can try them, and a point whose
     * fetch or parse fails is noted and the walk continues. Only the exhausted list is a verdict. */
    /** @internal The key carries the issuer the certificate names, not the URL alone. One URL
     * serving several issuers' lists is an ordinary hosting arrangement, and a key that ignores
     * the issuer hands the first certificate's list to the next certificate and suppresses its
     * fetch, so which certificate was validated first decides the second one's verdict. */
    var parsed = state.crlCache.get(_crlCacheKey(url, cert.issuer.bytes, issuer.workingPublicKey), ctx.time);
    var fetchedBytes = 0;
    if (parsed === null) {
      try {
        var got = await _fetchOne(state, { method: "GET", url: url, headers: { accept: "application/pkix-crl" } },
          "a CRL fetch from " + url);
        if (got.contentType !== null && got.contentType !== "application/pkix-crl") {
          _append(state.notes, "the CRL from " + url + " carried content-type " + guard.text.showValue(got.contentType));
        }
        /** @internal RFC 5280 sec. 4.2.1.13 with RFC 2585 sec. 3: the body is exactly one DER
         * CertificateList. One strict parser reads it, chosen by where the URL came from, so a PEM
         * body, a bundle of two CRLs or a PKCS#7 wrapper is refused rather than unwrapped. */
        parsed = crlSchema.parse(got.body);
        fetchedBytes = got.body.length;
      } catch (e) {
        _append(state.notes, "a CRL fetch from " + url + " failed: " + _say(e));
        if (state.fetches.count() >= state.maxFetches || state.deadline.expired()) break;
        continue;
      }
    }
    _append(gathered, parsed);
    /** @internal Whether this CRL is the issuer's, asked once and used twice: it decides whether
     * the locations the CRL names are worth opening, and whether it may be kept. A CRL fetched
     * over a plaintext hop can be replaced in transit, so a base that parses says nothing about
     * who wrote it, and the `freshestCRL` of one that did not verify is the replacement's choice
     * of destination rather than the issuer's. */
    var authentic = await _isIssuers(state, parsed, issuer);
    /** @internal RFC 5280 sec. 6.3.3(a) allows the delta location to be named by the certificate
     * or by the base CRL, so both are read. The certificate's own freshestCRL is the certificate's
     * to name, and the path already authenticated the certificate; the base CRL's is only followed
     * once the base is the issuer's. A delta settles nothing on its own, which is why these are
     * fetched beside a base rather than tried as candidates of their own. */
    var deltaUrls = authentic ? _deltaUrlsFor(parsed, state) : [];
    if (!authentic) _append(state.notes, "a CRL from " + url + " did not verify under the issuer's key, so the locations it names were not followed");
    for (var cd = 0; cd < (certDeltas || []).length; cd++) _append(deltaUrls, certDeltas[cd].url);
    for (var d = 0; d < deltaUrls.length && state.useDeltas; d++) {
      if (asked.has(deltaUrls[d]) || state.deadline.expired()) continue;
      if (!_takeUrl(state, deltaUrls[d])) continue;
      asked.add(deltaUrls[d]);
      try {
        var dg = await _fetchOne(state, { method: "GET", url: deltaUrls[d], headers: { accept: "application/pkix-crl" } },
          "a delta CRL fetch from " + deltaUrls[d]);
        _append(gathered, crlSchema.parse(dg.body));
      } catch (e) {
        _append(state.notes, "a delta CRL fetch failed: " + _say(e));
      }
    }
    var interim = await state.crlChecker(gathered, { useDeltas: state.useDeltas }).check(cert, issuer, ctx);
    if (interim && (interim.status === "good" || interim.status === "revoked")) {
      if (authentic) _keep(state, url, parsed, fetchedBytes, issuer.workingPublicKey);
      return { status: interim.status, reason: "a CRL from " + url,
        revocationReason: _reasonCodeOf(interim), revocationTime: interim.revocationTime };
    }
  }
  if (gathered.length === 0) throw E("path/revocation-fetch-failed", "no CRL was fetched");
  var last = await state.crlChecker(gathered, { useDeltas: state.useDeltas }).check(cert, issuer, ctx);
  return { status: (last && last.status) || "unknown", reason: (last && last.reason) || "the fetched CRLs did not settle the status",
    revocationReason: _reasonCodeOf(last), revocationTime: last && last.revocationTime };
}

/** @internal `crlChecker` names the CRLReason integer `reasonCode` and `verifyOcspResponse` names it
 * `revocationReason`. This verb answers from either source, so it reads both and reports the one
 * name. Reading only the OCSP name off a CRL verdict drops the reason from every CRL revocation. */
function _reasonCodeOf(verdict) {
  if (verdict == null) return undefined;
  var code = verdict.revocationReason;
  if (typeof code !== "number") code = verdict.reasonCode;
  return typeof code === "number" ? code : undefined;
}

/** @internal The delta locations a base CRL names in its own freshestCRL extension. The certificate's
 * own freshestCRL is read beside it by the caller, so both sources RFC 5280 sec. 6.3.3(a) allows are
 * covered. */
function _deltaUrlsFor(parsedCrl, state) {
  var out = [];
  var decoded = _softDecode(parsedCrl, OID_FRESHEST, state.notes);
  if (decoded === null) return out;
  var cands = _crlCandidates(decoded, state.net, state.notes);
  for (var c = 0; c < cands.length; c++) _append(out, cands[c].url);
  return out;
}

/**
 * @primitive  pki.path.fetchingChecker
 * @signature  pki.path.fetchingChecker(opts) -> { check }
 * @since      0.8.8
 * @status     stable
 * @spec       RFC 5280, RFC 6960, RFC 5019
 * @related    pki.path.crlChecker, pki.path.ocspChecker, pki.ocsp.httpRequest
 *
 * A revocation checker that fetches what it needs, for `pki.path.validate`'s
 * `opts.revocationChecker`. The shipped checkers are handed their CRLs and responses; this one
 * reads the locations out of the certificate and asks for them over `opts.transport`.
 *
 * Fetching is off unless an operator builds this and passes it, which is how `opts.fetchAia`
 * works: the default validation touches no network. It runs during `pki.path.validate` and not
 * during `pki.path.build`, because RFC 5019 sec. 3.2 has a status check requested only after
 * the chain's signatures are validated, and a build that fetched per candidate path would ask
 * about certificates it has not yet accepted.
 *
 * OCSP is attempted first and a CRL after it, which RFC 5019 sec. 3.1 directs. The responder
 * URL comes from an authorityInfoAccess AccessDescription whose accessMethod is id-ad-ocsp;
 * the CRL URLs come from cRLDistributionPoints, and never from authorityInfoAccess, which
 * RFC 5280 sec. 4.2.2.1 states outright. A distribution point is fetched only as a `fullName`
 * carrying a URI whose scheme this client speaks: an ldap or ftp point, a
 * nameRelativeToCRLIssuer, and a point naming a cRLIssuer and no location are each counted as
 * a skip, so a certificate naming no fetchable point reads as that and never as a failed fetch.
 *
 * Nothing this module fetches is trusted by having been fetched. A CRL goes to
 * `pki.path.crlChecker` and a response to `pki.path.verifyOcspResponse`, which are the one
 * place each rule lives: the issuer match, the cRLSign authorization, the IDP scope, the
 * sec. 6.3.3(b) correspondence, the CertID match, the responder authorization and both
 * currency windows. The structure a body is parsed as is decided by which extension named the
 * URL, so a Content-Type header is reported on a mismatch and never selects a parser.
 *
 * Every fault is an undetermined status carrying its reason, and `check` throws nothing: a
 * transport fault, a non-200, an unparsable body, a stale object and a non-successful
 * OCSPResponseStatus all land on `{ status: "unknown", reason }`. That is what keeps
 * `opts.softFail` meaningful, since a checker that throws is not waivable. A configuration
 * fault, such as a missing transport or a cap above the toolkit's own, throws here at
 * construction.
 *
 * The verdict names the source that answered and lists the locations skipped and the faults
 * noted in its `reason`; a `revoked` verdict adds `revocationReason` (the CRLReason integer)
 * and `revocationTime` from whichever source decided it. `pki.path.validate` carries all three
 * onto the certificate's `revocation` check row.
 *
 * Plaintext `http` is accepted by default, because a CRL and an OCSP response are signed
 * objects whose signatures this toolkit verifies, and because an https-only revocation fetch
 * needs the responder's own certificate validated first. `allowPlaintextHttp: false` narrows
 * it to https. The SSRF guards do not move either way: no private, loopback or link-local
 * destination, no redirect followed, a response-size cap, a per-certificate URL cap, a total
 * fetch count and a wall-clock deadline across the whole validation.
 *
 * A URL taken from a certificate names a destination the certificate chose, so the two forms are
 * decided in different places. An address literal is decided here and a private, loopback or
 * link-local one is a skip. A name is decided by whatever resolves it, which is inside the
 * transport, so a hostname candidate is a skip unless the transport declares
 * `blocksPrivateAddresses === true` on itself, the flag the transport `pki.transport.https(defaults)`
 * returns sets and backs by filtering the resolved address and pinning it for the connection.
 * `pki.transport.https` is the factory rather than a transport, so pass what it returns. Without
 * that declaration a certificate naming `crl.internal.example` would reach whatever the resolver
 * returns.
 *
 * `maxPerCert` counts the distinct destinations one certificate sends this client to across both
 * routes together, so a certificate naming five responders and five distribution points reaches
 * the figure, not twice it. `maxFetches` and `totalDeadlineMs` bound a validation rather than a
 * certificate: `pki.path.validate` calls a checker once per certificate and again for each anchor
 * it tries, and all of those share one budget. A checker is reusable, each validation starting
 * from the figures again; a `check` called directly is a validation of its own.
 *
 * A verified response is cached in process, keyed on the CertID and the responder URL, and a
 * CRL on its request URL and the issuer name it carries. Reuse is decided from the signed
 * thisUpdate and nextUpdate and from nothing else, which RFC 5019 sec. 7.5 directs; the HTTP
 * caching headers are not read.
 *
 * An `ldap` distribution point is not fetched. That is a second protocol client rather than a
 * flag, and it is re-opened when an operator presents a deployment whose only distribution
 * point is one. An `ftp` point is a permanent non-goal.
 *
 * @opts  transport         REQUIRED. The `pki.transport` seam, or any `(request) -> Promise`
 *                          of the same shape. A transport that does not declare that it blocks
 *                          private addresses is refused a hostname.
 * @opts  allowPlaintextHttp  Whether an `http` URL is fetched. Default `true`.
 * @opts  useDeltas         Whether a freshestCRL delta is fetched and merged. Default `true`.
 * @opts  nonce             Whether an OCSP request carries a 32-octet nonce. Default `false`,
 *                          since a pre-produced response carries none and the currency window
 *                          is the replay bound. Set, the response must echo the nonce or the
 *                          status is undetermined and the route falls through to the CRL.
 * @opts  tls               Passed to the transport for an https URL.
 * @opts  maxFetches        Requests across one validation. Default `C.LIMITS.REVOCATION_MAX_FETCHES`.
 * @opts  maxPerCert        Distinct destinations one certificate names, responders and distribution
 *                          points counted together. Default `C.LIMITS.REVOCATION_MAX_PER_CERT`.
 * @opts  maxResponseBytes  Default `C.LIMITS.REVOCATION_MAX_RESPONSE_BYTES`.
 * @opts  totalDeadlineMs   Wall clock across one validation. Default `C.LIMITS.REVOCATION_TOTAL_DEADLINE_MS`.
 * @opts  sourceTimeoutMs   Per request, narrowed to whatever the deadline has left; default
 *                          `C.LIMITS.REVOCATION_SOURCE_TIMEOUT_MS`.
 * @opts  retries           Attempts at the OCSP responder before the CRL is tried. Default `1`.
 * @example
 *   // pki.transport.https is the factory; the transport is what it returns, and only that
 *   // carries the blocksPrivateAddresses declaration a hostname destination needs.
 *   var checker = pki.path.fetchingChecker({ transport: pki.transport.https({}) });
 *   console.log(typeof checker.check);
 */
function fetchingChecker(opts) {
  opts = guard.identifier.optionsObject(opts, E, "path/bad-input", "fetchingChecker: opts");
  guard.identifier.assertKnownKeys(opts, CHECKER_OPTS, E, "path/bad-input",
    "pki.path.fetchingChecker has an unknown option. The unknown option was: ");
  /** @internal The checked value is the one used. Reading the option a second time would ask an
   * accessor twice, so the transport that passed the door is the transport that gets called. */
  var transport = guard.identifier.assertCallable(opts.transport, E, "path/bad-input",
    "fetchingChecker: opts.transport", TRANSPORT_SHAPE);
  var allowPlaintextHttp = opts.allowPlaintextHttp === undefined ? true : opts.allowPlaintextHttp === true;
  var cfg = {
    transport: transport,
    /** @internal Read off the transport once, here, beside the transport itself: a flag read again
     * at fetch time would be a second read of a caller's object, and the value that passed the
     * door is the value the rule is applied on. */
    net: intrinsic.freeze({ allowHttp: allowPlaintextHttp, guardsAddresses: _declaresAddressGuard(transport) }),
    allowPlaintextHttp: allowPlaintextHttp,
    useDeltas: !(opts.useDeltas === false),
    nonce: opts.nonce === true,
    tls: opts.tls,
    maxFetches: guard.limits.cap(opts.maxFetches, "fetchingChecker: opts.maxFetches", LIMITS.REVOCATION_MAX_FETCHES,
      { E: E, code: "path/bad-input", min: 1, max: LIMITS.REVOCATION_MAX_FETCHES }),
    maxPerCert: guard.limits.cap(opts.maxPerCert, "fetchingChecker: opts.maxPerCert", LIMITS.REVOCATION_MAX_PER_CERT,
      { E: E, code: "path/bad-input", min: 1, max: LIMITS.REVOCATION_MAX_PER_CERT }),
    maxResponseBytes: guard.limits.cap(opts.maxResponseBytes, "fetchingChecker: opts.maxResponseBytes", LIMITS.REVOCATION_MAX_RESPONSE_BYTES,
      { E: E, code: "path/bad-input", min: 1, max: LIMITS.REVOCATION_MAX_RESPONSE_BYTES }),
    totalDeadlineMs: guard.limits.cap(opts.totalDeadlineMs, "fetchingChecker: opts.totalDeadlineMs", LIMITS.REVOCATION_TOTAL_DEADLINE_MS,
      { E: E, code: "path/bad-input", min: 1, max: LIMITS.REVOCATION_TOTAL_DEADLINE_MS }),
    sourceTimeoutMs: guard.limits.cap(opts.sourceTimeoutMs, "fetchingChecker: opts.sourceTimeoutMs", LIMITS.REVOCATION_SOURCE_TIMEOUT_MS,
      { E: E, code: "path/bad-input", min: 1, max: LIMITS.REVOCATION_SOURCE_TIMEOUT_MS }),
    retries: guard.limits.cap(opts.retries, "fetchingChecker: opts.retries", 1, { E: E, code: "path/bad-input", min: 0, max: 4 }),
    crlChecker: pathValidate.crlChecker,
    verifyOcspResponse: pathValidate.verifyOcspResponse,
    parseRequest: ocspSchema.parseRequest,
  };
  var cache = _makeCache(LIMITS.REVOCATION_CACHE_MAX_ENTRIES, LIMITS.REVOCATION_CACHE_MAX_BYTES);
  var crlCache = _makeCache(LIMITS.REVOCATION_CACHE_MAX_ENTRIES, LIMITS.REVOCATION_CACHE_MAX_BYTES);
  /** @internal `maxFetches` and `totalDeadlineMs` bound a validation, and a validation is several
   * `check` calls: one per certificate on the path, and the set again for each anchor tried. A
   * budget minted per call would be those figures multiplied by the path length, which is a bound
   * the operator did not set. `pki.path.validate` names its run and the budget is held against that
   * name, so the certificates of one path share it. The map is weak, so the entry goes when the
   * validation does and a checker is reusable at its full figure on the next one. A `check` called
   * directly, with no run named, is its own validation and gets its own budget. */
  var budgets = new intrinsic.WeakMap();
  function budgetFor(run) {
    var fresh = {
      deadline: guard.limits.deadline(cfg.totalDeadlineMs),
      fetches: guard.limits.counter(cfg.maxFetches, E, "path/revocation-fetch-failed", "revocation fetch"),
    };
    if (run === null || typeof run !== "object") return fresh;
    var held = intrinsic.weakGet(budgets, run);
    if (held !== undefined) return held;
    intrinsic.weakSet(budgets, run, fresh);
    return fresh;
  }

  return {
    check: async function (cert, issuer, ctx) {
      var notes = [], skips = [];
      var budget = budgetFor(ctx == null ? null : ctx.run);
      var state = intrinsic.assign(intrinsic.create(null), cfg, {
        notes: notes, cache: cache, crlCache: crlCache,
        deadline: budget.deadline,
        fetches: budget.fetches,
        urls: new intrinsic.Set(),
      });
      var ocspCands, crlCands, certDeltas;
      try {
        ocspCands = _ocspCandidates(_softDecode(cert, OID_AIA, skips), cfg.net, skips);
        crlCands = _crlCandidates(_softDecode(cert, OID_CDP, skips), cfg.net, skips);
        var fresh = _softDecode(cert, OID_FRESHEST, skips);
        certDeltas = (fresh && cfg.useDeltas) ? _crlCandidates(fresh, cfg.net, skips) : [];
      } catch (e) {
        return _unknown("the revocation locations could not be read: " + _say(e), notes, skips);
      }
      if (ocspCands.length === 0 && crlCands.length === 0) {
        return _unknown("the certificate names no revocation location this client fetches", notes, skips);
      }
      /** @internal RFC 5019 sec. 3.1: the responder first, the CRL after a configured timeout and
       * number of retries. A responder that answers `revoked` or `good` ends it; anything else
       * falls through, because sec. 5 of RFC 6960 makes the CRL the fallback and never an
       * assumption of good standing. */
      var lastReason = null;
      for (var a = 0; a <= cfg.retries && ocspCands.length > 0; a++) {
        for (var o = 0; o < ocspCands.length; o++) {
          if (!_takeUrl(state, ocspCands[o].url)) {
            _append(skips, "a responder beyond the maxPerCert destinations this certificate may name");
            break;
          }
          try {
            var got = await _tryOcsp(state, cert, issuer, ctx, ocspCands[o]);
            if (got.status === "good" || got.status === "revoked") return _verdict(got, notes, skips);
            lastReason = got.reason + " reported " + got.status;
          } catch (e) { lastReason = _say(e); }
        }
      }
      if (crlCands.length > 0) {
        try {
          var viaCrl = await _tryCrl(state, cert, issuer, ctx, crlCands, certDeltas);
          if (viaCrl.status === "good" || viaCrl.status === "revoked") return _verdict(viaCrl, notes, skips);
          lastReason = viaCrl.reason;
        } catch (e2) { lastReason = _say(e2); }
      }
      return _unknown(lastReason || "no revocation source answered", notes, skips);
    },
  };
}

/** @internal Every reason this module reports about a fault it did not cause passes through here,
 * and the value is the transport's: `check` promises a verdict rather than a throw, and a value
 * whose `message` refuses to be read would break that promise at the one place that formats it.
 * @guard-via guard.text.describeThrown */
function _say(e) { return guard.text.describeThrown(e); }

function _verdict(got, notes, skips) {
  return guard.verdict.of({
    status: got.status, reason: _reason(got.reason, notes, skips),
    revocationReason: got.revocationReason, revocationTime: got.revocationTime,
  });
}

function _unknown(reason, notes, skips) {
  return guard.verdict.of({ status: "unknown", reason: _reason(reason, notes, skips) });
}

/** @internal A skip and a failure are carried separately into the one reason string, so an operator
 * reading an undetermined verdict can tell a blocked port from a certificate that names nothing
 * fetchable. The verdict itself is the same either way, which is why this is a reason and not a
 * second error code. */
function _reason(head, notes, skips) {
  var parts = [head];
  if (skips.length) _append(parts, "skipped: " + skips.join("; "));
  if (notes.length) _append(parts, "noted: " + notes.join("; "));
  return parts.join(" | ");
}

module.exports = { fetchingChecker: fetchingChecker };
