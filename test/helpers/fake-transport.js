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

function fakeTransport(script) {
  var calls = [];
  function transport(request) {
    var i = calls.length;
    calls.push(request);
    var r = typeof script === "function" ? script(request, i)
          : (Array.isArray(script) ? script[i] : script);
    if (!r) return Promise.reject(new Error("fakeTransport: no scripted response for call " + i));
    return Promise.resolve({ status: r.status, headers: r.headers || {}, body: r.body == null ? "" : r.body });
  }
  transport.calls = calls;
  return transport;
}

module.exports = { fakeTransport: fakeTransport };
