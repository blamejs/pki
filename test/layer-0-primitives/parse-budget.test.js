// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the per-parse resource budget and the door that enforces it.
 *
 * A format parser takes decode caps from its caller. The hard part is not threading them: it
 * is that a resource failure must never become a semantic answer. There are roughly 230
 * swallowing catches in lib/, and an earlier attempt at this feature was withdrawn after two
 * of them converted "over budget" into "this value is absent", which changed a verdict.
 *
 * So the budget latches on exhaustion and the door re-reads that latch after the walk returns
 * and before it hands back a result. A swallow may absorb the exception; it cannot clear the
 * latch, and it cannot make the door return. The vectors below drive that path with a schema
 * that swallows exactly the way the real ones do.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var pkix = require("../../lib/schema-pkix");
var schema = require("../../lib/schema-engine");
var limits = require("../../lib/guard-limits");
var errors = require("../../lib/framework-error");
var b = pki.asn1.build;

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || e.name; } }

var ProbeError = errors.defineClass("ProbeError");
var NS = pkix.makeNS("probe", ProbeError, pki.oid);

// A real certificate is the shipped consumer path for the door vectors.
var CERT = pkix.pemDecode(helpers.vectors.CERT_EC_PEM, "CERTIFICATE", errors.PemError);

function factoryOpts(topSchema) {
  return {
    topSchema: topSchema, ns: NS, ErrorClass: ProbeError, PemError: ProbeError,
    prefix: "probe", what: "a probe structure", pemLabel: "CERTIFICATE",
  };
}

// ---- the caller's caps reach the parser at all ----------------------------
function testCapsReachTheParser() {
  check("CONTROL: a certificate parses with no options", pki.schema.x509.parse(CERT).version === 3);
  check("CONTROL: a certificate parses under a generous cap",
    pki.schema.x509.parse(CERT, { maxBytes: 1 << 20 }).version === 3);
  check("a maxBytes below the input size refuses",
    code(function () { pki.schema.x509.parse(CERT, { maxBytes: 16 }); }) === "x509/too-large");
  check("the refusal is the format's own error class",
    (function () {
      try { pki.schema.x509.parse(CERT, { maxBytes: 16 }); return false; }
      catch (e) { return e instanceof pki.errors.PkiError; }
    })());
  // A budget exhaustion is not handed to a caller as its own class: the door converts it.
  check("a caller never sees a raw budget exhaustion",
    (function () {
      try { pki.schema.x509.parse(CERT, { maxBytes: 16 }); return false; }
      catch (e) { return limits.isBudgetExceeded(e) === false; }
    })());
}

// ---- the option surface is closed and tighten-only ------------------------
function testOptionSurface() {
  check("an unknown option is named rather than ignored",
    code(function () { pki.schema.x509.parse(CERT, { maxByte: 1000 }); }) === "x509/bad-input");
  check("the message names the option a caller misspelled",
    (function () {
      try { pki.schema.x509.parse(CERT, { maxByte: 1000 }); return false; }
      catch (e) { return String(e.message).indexOf("maxByte") !== -1; }
    })());
  check("a non-object options argument is refused",
    code(function () { pki.schema.x509.parse(CERT, 42); }) === "x509/bad-input");
  check("CONTROL: an absent options argument is fine", pki.schema.x509.parse(CERT).version === 3);

  // A cap may only tighten. Raising one past the built-in ceiling would let a caller hand
  // themselves more resource than the toolkit's own default allows.
  check("a maxBytes above the default ceiling is refused",
    code(function () { pki.schema.x509.parse(CERT, { maxBytes: pki.C.LIMITS.DER_MAX_BYTES + 1 }); }) === "x509/bad-input");
  check("a maxDepth above the default ceiling is refused",
    code(function () { pki.schema.x509.parse(CERT, { maxDepth: pki.C.LIMITS.DER_MAX_DEPTH + 1 }); }) === "x509/bad-input");
  check("CONTROL: a cap exactly at the default is accepted",
    pki.schema.x509.parse(CERT, { maxBytes: pki.C.LIMITS.DER_MAX_BYTES }).version === 3);
  check("a negative cap is refused",
    code(function () { pki.schema.x509.parse(CERT, { maxBytes: -1 }); }) === "x509/bad-input");
  check("a non-integer cap is refused",
    code(function () { pki.schema.x509.parse(CERT, { maxBytes: 1.5 }); }) === "x509/bad-input");
}

// ---- a resource option never changes which encodings are accepted ---------
function testCapsDoNotChangeAcceptance() {
  // The withdrawn attempt aliased the caps object and then wrote `ber = true` onto it, so
  // asking for a tighter cap quietly downgraded every nested decode to BER. The caller's
  // object must come back untouched, and strictness must not move.
  var opts = { maxBytes: 1 << 20 };
  pki.schema.x509.parse(CERT, opts);
  check("the caller's options object is not written to",
    Object.keys(opts).length === 1 && opts.maxBytes === (1 << 20));
  check("no strictness flag is added to the caller's object",
    opts.ber === undefined && opts.lenient === undefined);

  // A BER-only encoding stays refused whatever cap is asked for. An indefinite-length
  // SEQUENCE is the canonical one.
  var indefinite = Buffer.from("30800000", "hex");
  var noCaps = code(function () { pki.schema.x509.parse(indefinite); });
  var tightCap = code(function () { pki.schema.x509.parse(indefinite, { maxBytes: 4 }); });
  var looseCap = code(function () { pki.schema.x509.parse(indefinite, { maxBytes: 1 << 20 }); });
  check("a BER encoding is refused with no caps", noCaps !== "NO-THROW");
  check("and under a generous cap", looseCap !== "NO-THROW");
  check("and under a tight cap", tightCap !== "NO-THROW");
  check("asking for a tighter cap does not change what is accepted", looseCap === noCaps);
}

// ---- the door re-read: absorbing the throw changes nothing ----------------
function testSwallowedBudgetStillRefuses() {
  // A schema whose build swallows everything, which is the shape that sank the earlier
  // attempt: `catch (_e) { return <a semantic answer> }`. It trips the budget first, so the
  // walk returns a perfectly ordinary-looking result with the exception absorbed.
  function swallowingSchema() {
    return schema.seq([schema.field("n", schema.integerLeaf())], {
      assert: "sequence", code: "probe/bad-shape", what: "Probe",
      // The swallow here is the subject under test, not a shortcut: it stands in for the
      // shape that sank the earlier attempt, which read an absent value as a semantic answer.
      // The caught error is kept and reported, so this cannot hide some other throw.
      build: function (m, ctx) {
        var caught = null;
        try {
          ctx.budget.trip("a nested decode");
        } catch (e) {
          caught = e;
        }
        if (caught === null) return { absorbed: false, caught: null };
        return { absorbed: true, caught: caught };
      },
    });
  }

  var der = b.sequence([b.integer(1n)]);
  var opts = factoryOpts(swallowingSchema());

  // Proof the swallow really does absorb: driven directly, with a budget on the context and
  // no door above it, the schema returns its semantic answer and the exception is gone.
  var directNs = { prefix: "probe", E: NS.E, oid: pki.oid, budget: limits.budget({ maxBytes: 10 }) };
  var direct = schema.walk(swallowingSchema(), pki.asn1.decode(der), directNs).result;
  check("CONTROL: the swallowing schema absorbs the exhaustion on its own", direct.absorbed === true);
  check("CONTROL: and what it absorbed was the budget exhaustion, not some other throw",
    limits.isBudgetExceeded(direct.caught) === true);
  check("CONTROL: and the budget it tripped is latched", directNs.budget.exhausted() === true);

  // Through the door, the same schema cannot return. The latch outlives the catch.
  check("a budget exhaustion absorbed inside the walk still refuses at the door",
    code(function () { pkix.runParse(der, opts, {}); }) === "probe/too-large");
  check("and the refusal is the door's typed error, not the absorbed answer",
    (function () {
      try { pkix.runParse(der, opts, {}); return false; }
      catch (e) { return e instanceof ProbeError && e.code === "probe/too-large"; }
    })());

  // CONTROL: the same door with a schema that does not trip returns normally, so the refusal
  // above is the latch and not the door refusing everything.
  var quiet = schema.seq([schema.field("n", schema.integerLeaf())], {
    assert: "sequence", code: "probe/bad-shape", what: "Probe",
    build: function () { return { absorbed: false }; },
  });
  check("CONTROL: a schema that never trips the budget parses through the same door",
    pkix.runParse(der, factoryOpts(quiet), {}).absorbed === false);
}

// ---- the budget reaches a parse through every door shape ------------------
function testEveryDoorShapeCarriesTheOptions() {
  // A recording parser wraps the plain one to record provenance. The earlier attempt lost the
  // caller's options here, because the wrapper took one argument and passed one on.
  // Every format door the orchestrator publishes, driven with the same certificate bytes.
  // What is asserted per door is not that a certificate parses there, since most of these
  // read a different structure, but that a cap the caller names REACHES the decode: a tiny
  // cap must change the verdict to the format's own resource refusal. A door that dropped
  // the argument would report its ordinary bad-input or bad-der instead.
  // Every published parse function, the format-detecting orchestrator included. Walking the
  // namespaces alone misses `pki.schema.parse` itself, which is the door an operator holding
  // unidentified bytes reaches for first.
  function everyParseDoor() {
    var doors = [];
    Object.keys(pki.schema).forEach(function (key) {
      var v = pki.schema[key];
      if (typeof v === "function" && key.indexOf("parse") === 0) { doors.push(["schema." + key, v]); return; }
      if (!v || typeof v !== "object") return;
      Object.keys(v).forEach(function (fn) {
        if (typeof v[fn] === "function" && fn.indexOf("parse") === 0) doors.push([key + "." + fn, v[fn]]);
      });
    });
    return doors;
  }

  var tiny = { maxBytes: 8 };
  var dropped = [];
  everyParseDoor().forEach(function (row) {
    var got;
    try { row[1](CERT, tiny); got = "NO-THROW"; }
    catch (e) { got = (e && e.code) || e.name; }
    if (got.indexOf("/too-large") === -1) dropped.push(row[0] + " -> " + got);
  });
  check("every schema parse door applies a cap the caller named (" + dropped.join("; ") + ")",
    dropped.length === 0);

  // The same enumeration for the option surface. A door that delegates to another parser must
  // validate the caller's options in its OWN domain first: otherwise a misspelled option comes
  // back as the delegate's verdict about the content, which sends a reader to inspect bytes
  // that are fine. A door that takes an already-parsed structure must validate them too, or
  // the contract holds only for the input shapes that happen to reach a decode.
  var misreported = [];
  everyParseDoor().forEach(function (row) {
    var got;
    try { row[1](CERT, { maxByte: 10 }); got = "NO-THROW"; }
    catch (e) { got = (e && e.code) || e.name; }
    if (got.indexOf("/bad-input") === -1) misreported.push(row[0] + " -> " + got);
  });
  check("every schema parse door reports an unknown option as its own bad-input (" + misreported.join("; ") + ")",
    misreported.length === 0);
}

// A parser that hands its work to another parser still owns the caller's option surface. The
// CMC door takes an already-parsed CMS carrier as well as bytes, and that branch reaches no
// decode at all, so it is where an option contract goes unenforced if the check sits too deep.
function testDelegatingDoorsOwnTheirOptions() {
  var inner = b.sequence([b.integer(1n), b.sequence([]), b.sequence([]), b.sequence([]), b.sequence([])]);
  var eci = b.sequence([b.oid(pki.oid.byName("id-cct-PKIData")), b.contextConstructed(0, b.octetString(inner))]);
  var ci = b.sequence([b.oid(pki.oid.byName("signedData")),
    b.contextConstructed(0, b.sequence([b.integer(3n), b.set([]), eci, b.set([])]))]);
  var parsedCarrier = pki.schema.cms.parse(ci);

  // The carrier is accepted as far as the body, which is where this fixture stops being one;
  // what matters here is that the verdict is about the body and not about the options.
  check("CONTROL: an already-parsed carrier reaches the body without an option complaint",
    code(function () { pki.schema.cmc.parse(parsedCarrier); }) === "cmc/bad-pkidata");
  check("an unknown option is refused before the body, even on the already-parsed branch",
    code(function () { pki.schema.cmc.parse(parsedCarrier, { maxByte: 0 }); }) === "cmc/bad-input");
  check("a cap above the ceiling is refused on the already-parsed branch",
    code(function () { pki.schema.cmc.parse(parsedCarrier, { maxBytes: pki.C.LIMITS.DER_MAX_BYTES + 1 }); }) === "cmc/bad-input");
  check("CONTROL: a valid cap on the already-parsed branch still reaches the body",
    code(function () { pki.schema.cmc.parse(parsedCarrier, { maxBytes: 1024 }); }) === "cmc/bad-pkidata");

  // A caller's option object can answer differently each time it is read. A door that checks
  // the caller's object and then hands that same object to another parser has read each cap
  // twice, so the value enforced need not be the value approved. What the delegate receives
  // must be the snapshot the door validated.
  function shiftingCaps(first, later) {
    var reads = 0;
    return Object.defineProperty({}, "maxBytes", {
      enumerable: true,
      get: function () { reads += 1; return reads === 1 ? first : later; },
    });
  }
  check("a cap that changes between reads cannot slip past a delegating door",
    code(function () { pki.schema.cmc.parse(ci, shiftingCaps(0, undefined)); }) !== "NO-THROW");
  check("and the refusal is the zero-byte cap that was asked for first",
    code(function () { pki.schema.cmc.parse(ci, shiftingCaps(0, undefined)); }).indexOf("/too-large") !== -1);
  check("the same holds for the other delegating door",
    code(function () { pki.schema.tsp.parseToken(ci, shiftingCaps(0, undefined)); }).indexOf("/too-large") !== -1);
  // CONTROL: a stable zero-byte cap refuses the same way, so the assertions above are about
  // the second read and not about the accessor being rejected outright.
  check("CONTROL: a stable zero-byte cap refuses at the same door",
    code(function () { pki.schema.cmc.parse(ci, { maxBytes: 0 }); }).indexOf("/too-large") !== -1);
}

function run() {
  testCapsReachTheParser();
  testOptionSurface();
  testCapsDoNotChangeAcceptance();
  testSwallowedBudgetStillRefuses();
  testEveryDoorShapeCarriesTheOptions();
  testDelegatingDoorsOwnTheirOptions();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
