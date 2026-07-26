// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// CMP transfer test transport: fixtures + response constructors over the shared fakeTransport contract,
// so pki.cmp.transfer(url, message, opts) is driven end to end WITHOUT a socket. Every request/response
// PKIMessage is built by the shipped pki.cmp.build (raw DER), so a vector exercises the real codec the
// verb parses; the response constructors stamp the RFC 9811 content-types (application/pkixcmp, the
// legacy -poll variant, or a deliberately-wrong type) so the classifier state machine is covered
// deterministically. cmpOpts injects the fake transport plus a real trust anchor so a happy vector
// satisfies the default-transport anchor gate when it does not inject its own transport.

var fakeTransport = require("./fake-transport").fakeTransport;
var signing = require("./signing");

var PKIXCMP = "application/pkixcmp";

// A real EC signer -- its self-issued certificate DER doubles as the explicit trust anchor a default
// transport requires, and as the issued certificate inside a granting `ip` response.
var SIGNER = signing.makeSigner("ec-p256", { cn: "cmp-ca.example" });
var CERT_DER = SIGNER.cert;

var HDR = { sender: { directoryName: "CN=client" }, recipient: { directoryName: "CN=CA" }, transactionID: Buffer.alloc(16, 7) };
var SIG = { key: SIGNER.key, cert: SIGNER.cert };

// Build the fixture PKIMessages once (async: pki.cmp.build signs). Returns raw DER Buffers the transfer
// verb POSTs verbatim (the ir/p10cr request) or parses (the ip/error/pkiconf response).
function makeFixtures(pki) {
  return Promise.all([
    pki.cmp.build({ header: HDR, body: { ir: { certTemplate: { subject: [{ commonName: "leaf" }], publicKey: SIGNER.spki } } } }, SIG),
    pki.cmp.build({ header: HDR, body: { ip: { response: [{ certReqId: 0, status: { status: 0 }, certifiedKeyPair: { certificate: CERT_DER } }] } } }, SIG),
    pki.cmp.build({ header: HDR, body: { error: { pKIStatusInfo: { status: 2, failInfo: ["badRequest"] }, errorCode: 7, errorDetails: ["denied"] } } }, SIG),
    pki.cmp.build({ header: HDR, body: { pkiconf: null } }, SIG),
  ]).then(function (out) {
    return { irDer: out[0], ipDer: out[1], errorDer: out[2], pkiconfDer: out[3] };
  });
}

// Response constructors (fakeTransport response objects). A default application/pkixcmp response, the
// legacy -poll variant, and an arbitrary-status/-type response for the fail-closed branches.
function pkixcmp(status, bodyDer) { return { status: status, headers: { "content-type": PKIXCMP }, body: bodyDer }; }
function pkixcmpPoll(status, bodyDer) { return { status: status, headers: { "content-type": "application/pkixcmp-poll" }, body: bodyDer }; }
function resp(status, bodyDer, contentType) { return { status: status, headers: contentType ? { "content-type": contentType } : {}, body: bodyDer == null ? "" : bodyDer }; }

// Build the transfer opts: a fake transport driving `script` (an object|array|function per fakeTransport)
// plus a real anchor (so a vector that does NOT inject a transport still passes the default anchor gate).
// Returns { opts, transport } so a test asserts transport.calls.
function cmpOpts(script, extra) {
  var transport = fakeTransport(script);
  var opts = Object.assign({ transport: transport, tls: { anchors: [CERT_DER] } }, extra || {});
  return { opts: opts, transport: transport };
}

module.exports = {
  PKIXCMP: PKIXCMP, CERT_DER: CERT_DER, HDR: HDR, SIG: SIG,
  makeFixtures: makeFixtures, pkixcmp: pkixcmp, pkixcmpPoll: pkixcmpPoll, resp: resp, cmpOpts: cmpOpts,
};
