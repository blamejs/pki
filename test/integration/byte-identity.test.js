// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- registry-driven DER byte-identity against OpenSSL.
 *
 * The format set is DISCOVERED from the schema registry (`pki.schema.all()`),
 * never a hand-maintained list: for every registered format, OpenSSL generates
 * a real artifact and the toolkit must reproduce that exact DER from a
 * decode -> structural re-encode. The re-encoder rebuilds each TLV purely from
 * its DECODED components (tag class, constructed flag, tag number, and
 * content/children) via the toolkit's own encoder -- it deliberately discards
 * the raw byte slice the decoder retained -- so equality proves the toolkit's
 * DER encoder (identifier octets, minimal length octets, and nesting) agrees
 * with the independent implementation byte for byte, not that a slice was
 * copied back out.
 *
 * Future-proof by construction: because the loop is driven by the registry, a
 * newly-added `schema-<x>.js` shows up here automatically. A format with no
 * offline OpenSSL oracle is an explicit SKIP with its reason; a format that is
 * NEITHER generated NOR skipped fails the run -- so a new parser cannot ship
 * silently uncovered, and no static per-format row has to be added to keep the
 * harness aware of it.
 *
 * Runs under scripts/test-integration.js (each integration file as its own
 * process); the service-check gate confirms `openssl` before any file runs.
 */

var helpers = require("../helpers");
var check   = helpers.check;
var ctx     = require("./_interop-ctx");

var pki = ctx.pki;
var A   = pki.asn1;

// The raw class bits the low-level TLV encoder expects, keyed by the decoder's
// symbolic tag class. Rebuilding from these (rather than the retained bytes) is
// what makes the round-trip a real encoder check.
var CLASS_BITS = { universal: 0x00, application: 0x40, context: 0x80, private: 0xc0 };

function reencode(node) {
  var content = node.constructed
    ? Buffer.concat((node.children || []).map(reencode))
    : node.content;
  return A.encode(CLASS_BITS[node.tagClass], node.constructed, node.tagNumber, content);
}

// Write bytes to uniquely-named temp files, run the generator, and always remove
// them -- so a generator only expresses the OpenSSL recipe, never cleanup.
function withTmps(fn) {
  var made = [];
  function mk(bytes, ext) { var p = ctx.tmpFile(bytes || Buffer.alloc(0), ext); made.push(p); return p; }
  try { return fn(mk); }
  finally { made.forEach(function (p) { try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ } }); }
}

// A self-signed EC leaf (key + cert PEM paths) -- the shared input the CMS /
// OCSP / PKCS#12 recipes sign or reference.
function ecLeaf(mk, cn) {
  var key = mk(null, "key.pem"), cert = mk(null, "cert.pem");
  ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
    "-keyout", key, "-out", cert, "-days", "2", "-nodes", "-subj", "/CN=" + cn]);
  return { key: key, cert: cert };
}

// One recipe per format OpenSSL can emit offline as canonical DER. Each returns
// the DER Buffer; the key is the `pki.schema.all()` registry key.
var GENERATORS = {
  x509: function () {
    return withTmps(function (mk) {
      var leaf = ecLeaf(mk, "byte-identity-x509");
      return pki.schema.x509.pemDecode(ctx.fs.readFileSync(leaf.cert), "CERTIFICATE");
    });
  },
  csr: function () {
    return withTmps(function (mk) {
      var key = mk(null, "key.pem"), csr = mk(null, "req.pem");
      ctx.runOpenssl(["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-keyout", key, "-out", csr, "-nodes", "-subj", "/CN=byte-identity-csr"]);
      return pki.schema.csr.pemDecode(ctx.fs.readFileSync(csr), "CERTIFICATE REQUEST");
    });
  },
  pkcs8: function () {
    return withTmps(function (mk) {
      // `genpkey -algorithm EC` emits a traditional SEC1 EC key on some OpenSSL
      // builds and a PKCS#8 PrivateKeyInfo on others; convert explicitly so the
      // sample is unambiguously the PKCS#8 the registry parses, on every version.
      var key = mk(null, "key.pem"), out = mk(null, "pk8.der");
      ctx.runOpenssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key]);
      ctx.runOpenssl(["pkcs8", "-topk8", "-nocrypt", "-in", key, "-outform", "DER", "-out", out]);
      return ctx.fs.readFileSync(out);
    });
  },
  pkcs12: function () {
    return withTmps(function (mk) {
      var leaf = ecLeaf(mk, "byte-identity-p12");
      var p12 = mk(null, "store.p12");
      ctx.runOpenssl(["pkcs12", "-export", "-in", leaf.cert, "-inkey", leaf.key,
        "-out", p12, "-passout", "pass:byte-identity"]);
      return ctx.fs.readFileSync(p12);
    });
  },
  cms: function () {
    return withTmps(function (mk) {
      var leaf = ecLeaf(mk, "byte-identity-cms");
      var data = mk(Buffer.from("byte-identity\n", "utf8"), "data.txt"), out = mk(null, "cms.der");
      ctx.runOpenssl(["cms", "-sign", "-binary", "-outform", "DER", "-nodetach",
        "-signer", leaf.cert, "-inkey", leaf.key, "-in", data, "-out", out]);
      return ctx.fs.readFileSync(out);
    });
  },
  "ocsp-request": function () {
    return withTmps(function (mk) {
      var leaf = ecLeaf(mk, "byte-identity-ocsp");
      var out = mk(null, "ocspreq.der");
      // A self-issued pair is a legitimate (issuer, cert) for a status request; -reqout
      // writes the TimeStampReq-free OCSPRequest and exits without contacting a responder.
      ctx.runOpenssl(["ocsp", "-issuer", leaf.cert, "-cert", leaf.cert, "-reqout", out]);
      return ctx.fs.readFileSync(out);
    });
  },
  crl: function () {
    return withTmps(function (mk) {
      // A minimal CA: an empty index, a crlnumber seed, and a tiny [ca] config so
      // `ca -gencrl` emits a (revocation-free) CRL offline without a full CA tree.
      // Config paths use forward slashes so OpenSSL's parser accepts them on Windows.
      var key = mk(null, "cakey.pem"), cert = mk(null, "cacert.pem");
      var index = mk(Buffer.alloc(0), "index.txt"), crlnum = mk(Buffer.from("1000\n", "utf8"), "crlnumber");
      var out = mk(null, "crl.pem");
      var cnf = mk(Buffer.from(
        "[ca]\ndefault_ca = CA_default\n[CA_default]\n" +
        "database = " + index.replace(/\\/g, "/") + "\n" +
        "crlnumber = " + crlnum.replace(/\\/g, "/") + "\n" +
        "default_md = sha256\ndefault_crl_days = 30\n", "utf8"), "ca.cnf");
      ctx.runOpenssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-keyout", key, "-out", cert, "-days", "5", "-nodes", "-subj", "/CN=byte-identity-crl-ca"]);
      ctx.runOpenssl(["ca", "-config", cnf, "-gencrl", "-keyfile", key, "-cert", cert, "-out", out]);
      var der = pki.schema.crl.pemDecode(ctx.fs.readFileSync(out), "X509 CRL");
      // `openssl ca` writes backup/attr siblings next to the database + crlnumber it
      // was handed; withTmps only owns the paths it minted, so sweep these too.
      [crlnum + ".old", index + ".old", index + ".attr"].forEach(function (p) {
        try { ctx.fs.unlinkSync(p); } catch (_e) { /* best-effort */ }
      });
      return der;
    });
  },
};

// Registry formats with no offline OpenSSL oracle -- recorded as explicit skips
// (a skip is never a pass), so the coverage picture is honest and a format here
// is visibly awaiting an oracle rather than silently unchecked.
var ORACLE_ABSENT = {
  tsp:             "`openssl ts` needs a TSA key + config (and a responder for a token); no offline one-liner oracle",
  "ocsp-response": "an OCSP response must be signed by a responder/CA; no offline openssl oracle",
  crmf:            "`openssl cmp` is client-only (needs a live server); no offline CRMF generator",
  cmp:             "`openssl cmp` is client-only (needs a live server); no offline CMP generator",
  csrattrs:        "no openssl/NSS generator for the EST CsrAttrs wire format (RFC 8951 / 9908)",
  attrcert:        "openssl cannot emit RFC 5755 attribute certificates",
  "attrcert-v1":   "openssl cannot emit RFC 5755 attribute certificates",
};

function run() {
  var formats = pki.schema.all();
  check("byte-identity: formats discovered from the schema registry", formats.length > 0);

  var covered = 0, skipped = 0;
  formats.forEach(function (key) {
    var gen = GENERATORS[key];
    if (gen) {
      var der = gen();
      // The strict, canonical-DER decoder + detect-and-route orchestrator accept the
      // independent implementation's exact bytes -- the input side of interop. A reject
      // throws here (surfacing the real fault) rather than degrading to a boolean.
      var parsed = pki.schema.parse(der);
      check("byte-identity: " + key + " -- schema.parse accepts openssl's DER", parsed && typeof parsed === "object");
      // ...and the toolkit reproduces those exact bytes from decoded components.
      var round = reencode(A.decode(der));
      check("byte-identity: " + key + " -- toolkit re-encodes openssl's DER byte-identically (" + der.length + " B)",
        Buffer.isBuffer(round) && round.equals(der));
      covered += 1;
      return;
    }
    if (Object.prototype.hasOwnProperty.call(ORACLE_ABSENT, key)) {
      ctx.skip("byte-identity: " + key + " -- " + ORACLE_ABSENT[key]);
      skipped += 1;
      return;
    }
    // Future-proof tripwire: a newly-registered format that is neither generated
    // nor explicitly skipped fails here until it is classified -- this is what lets
    // the harness carry no static format list.
    check("byte-identity: " + key + " -- has an openssl generator or an explicit oracle-absent reason", false);
  });

  console.log("[byte-identity] " + formats.length + " registry format(s); " + covered +
    " byte-identity-checked against openssl; " + skipped + " skipped (no offline oracle)");
  check("byte-identity: the cert/CSR/key/PKCS12/CMS/OCSP/CRL formats are all covered", covered >= 7);
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); console.log("SKIPS " + helpers.getSkips()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
