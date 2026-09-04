// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
//
// fakeTransport(script) -> a transport(request) -> Promise<{status, headers, body}> test double for
// the shared pki.transport contract. NO socket is opened: it replays a scripted response so a verb's
// full state machine (redirect follow-loop, 401 auth retry, 202 surface) is driven deterministically.
// `script` is one of:
//   - a single { status, headers?, body? } object          -- one response, OR
//   - an array of them                                      -- multi-response (302->200 follow, 401->200 retry), OR
//   - a function (request, callIndex) -> response object    -- loop / stateful cases.
// transport.calls records every request handed in (method / url / headers / body) so a test can assert
// what crossed the seam and how many times -- a gate that must precede the transport proves calls.length===0.

// `opts.channel` drives the channel-binding seam: the real transport invokes a FUNCTION request body
// after the handshake with { protocol, cipher, peerCertificate, tlsUnique } and awaits bytes, a string,
// or a promise of either. Pass a channel object, or a function (callIndex) -> channel to hand each
// connection its own tls-unique (a redirect or auth retry is a NEW connection, so the body is rebuilt).
// The resolved bytes land in transport.bodies[i], so a test can decode what actually crossed the wire
// and prove which connection's binding it carries. A body callback that throws or rejects is reported
// the way the real transport reports it, as a transport error carrying the cause.
function fakeTransport(script, opts) {
  opts = opts || {};
  var calls = [];
  var bodies = [];
  var NO_CHANNEL = { protocol: null, cipher: null, peerCertificate: null, tlsUnique: null };
  function transport(request) {
    var i = calls.length;
    calls.push(request);
    var chan = typeof opts.channel === "function" ? opts.channel(i) : (opts.channel || NO_CHANNEL);
    var bodyP = typeof request.body === "function"
      ? Promise.resolve().then(function () { return request.body(chan); }).then(
        function (bytes) { return bytes; },
        function (e) {
          var te = new Error("the channel-binding body callback failed: " + ((e && e.message) || String(e)));
          te.code = (opts.errPrefix || "est") + "/transport-error";
          te.cause = e;
          throw te;
        })
      : Promise.resolve(request.body);
    return bodyP.then(function (resolvedBody) {
      bodies[i] = resolvedBody;
      var r = typeof script === "function" ? script(request, i)
            : (Array.isArray(script) ? script[i] : script);
      if (!r) throw new Error("fakeTransport: no scripted response for call " + i);
      // A script function may return the response object directly OR a Promise of it (a stateful async CA that
      // builds a signed response per request) -- resolve the thenable before reading its fields.
      // Forward a scripted `tls` verbatim (the real transport surfaces { protocol, cipher, peerCertificate }) so a
      // verb that inspects the negotiated session -- e.g. serverkeygen's non-NULL/anon/EXPORT cipher gate -- can be
      // driven deterministically; absent by default, so every existing vector is unaffected.
      return Promise.resolve(r).then(function (rr) {
        return { status: rr.status, headers: rr.headers || {}, body: rr.body == null ? "" : rr.body, tls: rr.tls };
      });
    });
  }
  transport.calls = calls;
  transport.bodies = bodies;
  return transport;
}

module.exports = { fakeTransport: fakeTransport };
