// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: pki.ocsp.httpRequest
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (CI PRs + nightly batch)
 * and OSS-Fuzz (continuous) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer the
 * engine mutates via coverage-guided fuzzing. Its seed corpus
 * (`fuzz/ocsp-http-request_seed_corpus/`) carries a request at each side
 * of the RFC 5019 sec. 5 GET boundary, one whose base64 is all padding,
 * and responder URLs with and without a trailing slash.
 *
 * The encoder is where a URL-normalization difference would hide: the
 * request rides in a path segment, so a byte that escapes the escaping
 * reaches the path, the query or the authority of a URL a client is about
 * to open.
 *
 * Contract: the call returns a request shape or throws a
 * `pki.errors.PkiError`. Beyond that, whatever it returns has to survive
 * the round trip a transport puts it through: `new URL()` must
 * re-serialize the GET URL unchanged, since a transport that renormalized
 * the path would send a request the responder cannot decode, and the
 * segment must decode back to the exact DER that went in.
 */

var pki = require("..");

module.exports.fuzz = function (data) {
  if (data.length < 2) return;
  var split = 1 + (data[data.length - 1] % (data.length - 1));
  var der = data.subarray(0, split);
  var tail = data.subarray(split, data.length - 1).toString("latin1");
  var url = "http://ocsp.example/" + tail.replace(/[^A-Za-z0-9/._~-]/g, "");

  var req;
  try {
    req = pki.ocsp.httpRequest(der, url);
  } catch (e) {
    if (e instanceof pki.errors.PkiError) return;
    throw e;
  }
  if (req.method !== "GET" && req.method !== "POST") {
    throw new Error("httpRequest answered with method " + JSON.stringify(req.method));
  }
  if (req.method === "POST") {
    if (!Buffer.isBuffer(req.body) || !req.body.equals(Buffer.from(der))) {
      throw new Error("a POST did not carry the DER it was given");
    }
    if (req.headers["content-type"] !== "application/ocsp-request") {
      throw new Error("a POST carried content-type " + JSON.stringify(req.headers["content-type"]));
    }
    return;
  }
  if (req.body !== null) throw new Error("a GET carried a body");
  if (req.url.length > 255) throw new Error("a GET URL is " + req.url.length + " bytes, over the RFC 5019 sec. 5 budget");
  if (/[\r\n]/.test(req.url)) throw new Error("the GET URL carries a CR or an LF");

  // A transport opens the URL through the platform parser, so a URL this encoder produced has
  // to survive it byte for byte: anything the parser would rewrite is a request the responder
  // receives in a form it did not encode.
  var reparsed;
  try { reparsed = new URL(req.url); }
  catch (e2) { throw new Error("the GET URL does not parse: " + e2.message); }
  if (reparsed.href !== req.url) {
    throw new Error("the GET URL is renormalized by the URL parser: " + req.url + " -> " + reparsed.href);
  }
  if (reparsed.search !== "") throw new Error("the request reached the query rather than the path");

  // The last path segment, percent-decoded and base64-decoded, is the DER that went in.
  var segment = reparsed.pathname.slice(reparsed.pathname.lastIndexOf("/") + 1);
  var decoded = Buffer.from(_unpercent(segment), "base64");
  if (!decoded.equals(Buffer.from(der))) {
    throw new Error("the encoded segment does not decode back to the request");
  }
};

function _unpercent(text) {
  var out = "", i = 0;
  while (i < text.length) {
    if (text.charAt(i) === "%") { out += String.fromCharCode(parseInt(text.slice(i + 1, i + 3), 16)); i += 3; }
    else { out += text.charAt(i); i += 1; }
  }
  return out;
}
