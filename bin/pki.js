#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * pki — command-line front-end for @blamejs/pki.
 *
 *   pki version                          print the package version
 *   pki oid <dotted|name>                resolve an OID <-> name
 *   pki parse <cert>                      parse an X.509 certificate to JSON
 *   pki inspect <file> [--asn1]           render whatever the file holds as text, or dump its TLV tree
 *   pki keygen --out <key> [--pub <spki>] generate a key pair; the private key to a file, never stdout
 *              [--alg NAME] [--pem]
 *   pki csr --key <k> --subject <dn>      a PKCS#10 request over the key's public half
 *              [--san a,b] [--out F] [--pem]
 *   pki issue (--key <k> --subject <dn>   a certificate, self-signed or from a supplied issuer
 *              | --csr <req>) [--ca]
 *              [--issuer-cert <c> --issuer-key <k>] [--days N] [--serial HEX] [--san a,b] [--out F] [--pem]
 *   pki fetch <https-url> --anchor <c>    the chain a live endpoint presents; NOT a verification
 *              [--system] [--out F] [--der]
 *   pki lint <file> [--profile P]         lint the structure the file holds; exit non-zero on an error finding
 *              [--severity S] [--json]
 *   pki convert <file> --to der|pem       transcode a DER/PEM file between the two encodings
 *              [--label LABEL]
 *   pki verify <cert>... --anchor <cert>  validate an ordered certification path (anchor->target)
 *              [--time ISO]
 *   pki sign <file> --cert <c> --key <k>  produce a CMS SignedData over the file (pki.cms.sign)
 *              [--detached] [--pss] [--digest D] [--pem] [--out F]
 *
 * The CLI is a thin operator convenience over the library surface: it validates its
 * arguments (entry-point tier — bad input exits non-zero with a message) and never does
 * anything the public API cannot. inspect / lint / convert / verify / sign compose pki.inspect,
 * pki.lint, the per-format PEM codecs, pki.path.validate, and pki.cms.sign respectively.
 */

var fs  = require("node:fs");
var pki = require("../index.js");

function fail(msg) {
  process.stderr.write("pki: " + msg + "\n");
  process.exit(1);
}

// Minimal flag parser: `--flag value` for value-taking flags, `--flag` for booleans, the
// rest are positionals in `_`. A value-taking flag whose value is absent or is itself another
// flag is a usage error (never silently coerced to `true`, which would make e.g. `--time`
// parse as `new Date(true)` = a real 1970 timestamp). No clustering, no `=value`.
var VALUE_FLAGS = { to: 1, profile: 1, severity: 1, label: 1, anchor: 1, time: 1, cert: 1, key: 1,
  digest: 1, out: 1, alg: 1, pub: 1, subject: 1, san: 1, days: 1, serial: 1, csr: 1,
  "issuer-cert": 1, "issuer-key": 1 };
function parseArgs(argv) {
  var out = { _: [] };
  for (var i = 0; i < argv.length; i++) {
    var a = argv[i];
    if (a.indexOf("--") === 0) {
      var key = a.slice(2);
      if (VALUE_FLAGS[key]) {
        if (i + 1 >= argv.length || argv[i + 1].indexOf("--") === 0) fail("--" + key + " requires a value");
        out[key] = argv[++i];
      } else { out[key] = true; }
    } else { out._.push(a); }
  }
  return out;
}

function readFileBytes(file) {
  try { return fs.readFileSync(file); } catch (e) { return fail("cannot read " + file + ": " + e.message); }
}

// A verb taking a bare positional still has to answer --help, which is the first flag anyone
// tries: without this, `pki oid --help` reports an unknown OID name and `pki parse --help` tries
// to open a file called --help. Every verb prints its own usage line for --help, -h and a missing
// argument; the flag-parsing verbs get the same answer from their existing usage checks.
function usageOrArg(arg, usage) {
  if (!arg || arg === "--help" || arg === "-h") fail(usage);
  return arg;
}

// For the library entry points (parse / inspect / lint / verify) that accept EITHER a DER
// Buffer or a PEM string and own the decode + error handling: hand a Buffer when the bytes
// are a well-formed DER structure, otherwise the text so the library pemDecodes it (and
// applies its own canonical-base64 policy). This defers ALL error handling to the library,
// which is what preserves the linter's never-throw survey -- malformed bytes become a fatal
// lint/unparseable finding rather than a CLI hard-fail. DER-first is unambiguous (a PEM file
// is ASCII text and never decodes as one DER TLV).
// The PEM grammar both readers match against: an uppercase A-Z0-9 label whose BEGIN and END agree.
// One definition, so the ambiguity check and the convert extractor cannot disagree about what a
// block is.
var PEM_BLOCK_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/;

function readForLib(file) {
  var bytes = readFileBytes(file);
  var isDer = true;
  try { pki.asn1.decode(bytes); } catch (_derErr) { isDer = false; }
  if (!isDer) return bytes.toString("latin1");   // not DER -- let the library pemDecode / report it
  // A short DER header can be entirely printable, so a file can be one complete DER value AND a
  // well-formed PEM block at once. Neither reading is wrong, so neither is chosen: reporting the
  // DER reading's parse failure would send the reader after a fault in the wrong structure.
  if (PEM_BLOCK_RE.test(bytes.toString("latin1"))) {
    return fail(file + " reads as both one complete DER value and a PEM block, so which was meant " +
      "cannot be read from the bytes: run `pki convert " + file + " --to pem` to settle it as the " +
      "DER value, or delete the bytes before its -----BEGIN line to settle it as the PEM block");
  }
  return bytes;
}

// For `convert`, which transcodes RAW bytes and bypasses the library parse: extract DER
// explicitly (a well-formed DER file as-is, or a canonical PEM body), failing on anything
// else. Returns { der, label } where `label` is the PEM armor when the input was PEM.
function readDer(file) {
  var bytes = readFileBytes(file);
  try { pki.asn1.decode(bytes); return { der: bytes, label: null }; }
  catch (_derErr) { /* not a single well-formed DER structure -- try PEM */ }
  // Match the library's PEM grammar exactly (an uppercase A-Z0-9 label, and ONLY CR/LF/TAB/
  // space ignored in the body -- not every JS whitespace), so convert is not a looser
  // validation path than the codecs it composes.
  var m = PEM_BLOCK_RE.exec(bytes.toString("latin1"));
  if (!m) return fail(file + ": input is neither a well-formed DER structure nor a PEM block");
  var b64 = m[2].replace(/[\r\n\t ]+/g, "");
  // Enforce CANONICAL base64 (RFC 4648 sec. 3.5), matching the library's fail-closed PEM
  // policy: Node's decoder silently drops invalid characters and tolerates non-canonical
  // trailing pad bits. Gate alphabet/length, then require that re-encoding reproduces the body.
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4 !== 0) return fail(file + ": malformed PEM base64");
  var der = Buffer.from(b64, "base64");
  if (der.toString("base64") !== b64) return fail(file + ": non-canonical PEM base64");
  return { der: der, label: m[1] };
}

function cmdVersion() {
  process.stdout.write("@blamejs/pki v" + pki.version + "\n");
}

function cmdOid(arg) {
  usageOrArg(arg, "usage: pki oid <dotted|name>");
  if (/^\d+(\.\d+)+$/.test(arg)) {
    var name = pki.oid.name(arg);
    process.stdout.write((name || "(unregistered)") + "\n");
  } else {
    var dotted = pki.oid.byName(arg);
    if (!dotted) fail("unknown OID name: " + arg);
    process.stdout.write(dotted + "\n");
  }
}

function cmdParse(file) {
  usageOrArg(file, "usage: pki parse <cert.pem|cert.der>");
  var cert;
  try { cert = pki.schema.x509.parse(readForLib(file)); } catch (e) { return fail(e.code + ": " + e.message); }
  var view = {
    version:            cert.version,
    serialNumber:       cert.serialNumberHex,
    subject:            cert.subject.dn,
    issuer:             cert.issuer.dn,
    notBefore:          cert.validity.notBefore.toISOString(),
    notAfter:           cert.validity.notAfter.toISOString(),
    signatureAlgorithm: cert.signatureAlgorithm.name || cert.signatureAlgorithm.oid,
    publicKeyAlgorithm: cert.subjectPublicKeyInfo.algorithm.name || cert.subjectPublicKeyInfo.algorithm.oid,
    extensions:         cert.extensions.map(function (e) { return { oid: e.oid, name: e.name, critical: e.critical }; }),
  };
  process.stdout.write(JSON.stringify(view, null, 2) + "\n");
}

// pki inspect <file> [--asn1] -- the human-readable render of whatever the file holds. It routes
// through pki.inspect.any, which detects the format and picks the report, so every format the
// library renders is reachable here. --asn1 asks for the structural TLV dump instead, which reads
// a file of any shape, including one no format detector recognizes.
function cmdInspect(args) {
  var file = args._[0];
  if (!file) fail("usage: pki inspect <file.pem|file.der> [--asn1]");
  try { process.stdout.write(args.asn1 ? pki.inspect.asn1(readForLib(file)) + "\n" : pki.inspect.any(readForLib(file))); }
  catch (e) { return fail(e.code + ": " + e.message); }
}

function pad(s, n) { while (s.length < n) s += " "; return s; }

// The lint verb for each structure `pki lint` detects, one entry per verb pki.lint ships. A file
// holding a structure with no lint verb (a key, a PKCS#12 store, an enrollment message) is refused
// by the name the detector gives it. `ocsp-request` has no verb: RFC 6960's linted profile is the
// response, and pki.lint.ocsp takes one.
var LINT_VERB_FOR = {
  "x509": "certificate", "csr": "csr", "crl": "crl", "ocsp-response": "ocsp",
  "cms": "cms", "tsp": "tsp", "attrcert": "attrcert",
};
// The usage line names the verbs from the table rather than from a list written beside it, so a
// verb added above cannot leave the usage naming a set the CLI does not have.
var LINT_USAGE = "usage: pki lint <" + Object.keys(LINT_VERB_FOR).map(function (k) {
  return LINT_VERB_FOR[k];
}).join("|") + "> [--profile <name>] [--severity <floor>] [--json]";

// pki lint <file> -- detect whether the file holds a certificate, a CRL or an OCSP response and
// lint it against that structure's profiles. Prints one line per finding and exits non-zero
// when any error/fatal finding is present (0 when the worst is advisory).
function cmdLint(args) {
  var file = args._[0];
  if (!file) fail(LINT_USAGE);
  var input = readForLib(file);
  // Bytes no detector recognizes (garbage, or a structure outside the detector's set) fall
  // through to the certificate verb, whose never-throw data path reports them as a fatal
  // lint/unparseable finding; a structure the detector DOES name but no profile covers is a
  // config-time refusal naming it, so a request is not silently linted as a certificate.
  var verb = "certificate", format;
  try { format = pki.schema.detectFormat(input); } catch (_e) { format = null; }
  if (format !== null) {
    verb = LINT_VERB_FOR[format];
    if (verb === undefined) {
      return fail(file + ": holds a " + format + " structure, and pki lint covers " +
        Object.keys(LINT_VERB_FOR).join(", "));
    }
  }
  var report;
  // Config-time misuse (unknown profile / bad severity) throws a typed LintError; the data
  // path never throws (malformed bytes become a fatal lint/unparseable finding).
  try { report = pki.lint[verb](input, { profile: args.profile, severity: args.severity }); }
  catch (e) { return fail(e.code + ": " + e.message); }
  if (args.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } else {
    report.findings.forEach(function (f) {
      process.stdout.write(pad(f.severity.toUpperCase(), 7) + " " + f.id + " -- " + f.message + "\n");
    });
    process.stdout.write("\n" + (report.findings.length || "no") + " finding(s); worst: " + (report.worst || "pass") + "\n");
  }
  // Set the exit CODE and let Node drain — process.exit() can truncate a buffered stdout
  // write to a pipe before it flushes.
  process.exitCode = (report.counts.error || report.counts.fatal) ? 1 : 0;
}

// The suite `keygen` produces with no --alg. ML-DSA-65 is the FIPS 204 middle level and the suite
// this toolkit leads with, so the post-quantum choice is the one an operator gets by default rather
// than the one they have to know to ask for.
var KEYGEN_DEFAULT_ALG = "ML-DSA-65";
// Owner-only on the platforms that enforce a file mode. On win32 Node does not apply the mode
// argument -- measured: a file created with 0o600 reports 0o666 -- so the file inherits the
// directory's ACL there and the help text says so rather than implying a guarantee.
var KEY_FILE_MODE = 0o600;
var KEYGEN_USAGE = "usage: pki keygen --out <key-file> [--pub <spki-file>] [--alg " +
  KEYGEN_DEFAULT_ALG + "] [--pem]\n" +
  "  The private key is written to --out and never to stdout. An existing file is never written\n" +
  "  over. The file is created owner-only where the platform enforces a file mode; on Windows the\n" +
  "  mode is not applied and the file inherits the directory's permissions.";

// Write a file that must not exist yet, with its mode set in the call that creates it: a chmod
// after the write leaves a window where the key is readable by anyone who can open the file.
function writeNewFile(file, bytes, mode) {
  try { fs.writeFileSync(file, bytes, { flag: "wx", mode: mode }); }
  catch (e) {
    if (e.code === "EEXIST") return fail(file + " already exists, and a key is never written over one");
    return fail("cannot write " + file + ": " + e.message);
  }
}

// pki keygen --out <file> -- generate a key pair and write the private key to a file. The public
// half goes to --pub when asked for, so an operator sending a public key does not have to hand over
// a file that also holds the private one.
function cmdKeygen(args) {
  if (!args.out) return fail(KEYGEN_USAGE);
  var alg = args.alg || KEYGEN_DEFAULT_ALG;
  return pki.key.generate(alg).then(function (pair) {
    return Promise.all([pki.key.export(pair.privateKey), pki.key.export(pair.publicKey)]);
  }, function (e) {
    return fail("keygen: cannot generate " + alg + ": " + (e.code || e.message));
  }).then(function (both) {
    if (both === undefined) return undefined;   // fail() already exited
    var privDer = both[0], pubDer = both[1];
    var priv = args.pem ? pki.schema.pkcs8.pemEncode(privDer, "PRIVATE KEY") : privDer;
    writeNewFile(args.out, priv, KEY_FILE_MODE);
    if (args.pub) writeNewFile(args.pub, args.pem ? _spkiPem(pubDer) : pubDer, undefined);
    process.stdout.write("wrote " + alg + " private key to " + args.out +
      (args.pub ? " and its public key to " + args.pub : "") + "\n");
  });
}
// The public half has no PEM codec of its own on the schema surface (an SPKI is not a format the
// parsers detect), so its armor is written here from the same grammar the codecs read.
function _spkiPem(der) {
  return "-----BEGIN PUBLIC KEY-----\n" +
    der.toString("base64").replace(/(.{1,64})/g, "$1\n") + "-----END PUBLIC KEY-----\n";
}

var CSR_USAGE = "usage: pki csr --key <key.pkcs8> --subject <dn> [--san name,name] [--out <file>] [--pem]\n" +
  "  A key path on a command line is visible in the process table to every user on this machine\n" +
  "  for as long as the process runs.";
var ISSUE_USAGE = "usage: pki issue (--key <key.pkcs8> --subject <dn> | --csr <request>)\n" +
  "                 [--issuer-cert <cert> --issuer-key <key>] [--days N] [--serial HEX]\n" +
  "                 [--ca] [--san name,name] [--out <file>] [--pem]\n" +
  "  With no issuer the certificate is self-signed by --key. An issuer needs both halves: a\n" +
  "  certificate with no key, or a key with no certificate, is refused rather than self-signed.\n" +
  "  A key path on a command line is visible in the process table to every user on this machine\n" +
  "  for as long as the process runs.";
var ISSUE_DEFAULT_DAYS = 365;

// --san takes a comma-separated list and the library classifies each name as a DNS name, an
// address, an address or a URI, so the CLI does not carry a second classifier.
function sanList(arg) {
  if (!arg) return undefined;
  var names = String(arg).split(",").map(function (s) { return s.trim(); }).filter(function (s) { return s.length > 0; });
  return names.length ? names : undefined;
}

// A DER or PEM file for a library entry point that takes either.
function _keyArg(file) { return _asPemOrDer(readFileBytes(file)); }

// --subject is a distinguished name, parsed as one and handed to the builders as the raw Name DER
// they accept: they read a bare string as a common name, so `--subject CN=x` would otherwise certify
// a CN whose value is the text "CN=x". A component with no attribute type is refused by
// pki.x509.parseDn, whose message names the one at fault.
function subjectArg(arg) {
  try { return pki.x509.parseDn(arg).bytes; }
  catch (e) { return fail("--subject is a distinguished name such as \"CN=host.example, O=Org\": " + e.message); }
}

function writeOrPrint(args, bytes) {
  if (!args.out) { process.stdout.write(bytes); return; }
  try { fs.writeFileSync(args.out, bytes); } catch (e) { return fail("cannot write " + args.out + ": " + e.message); }
  process.stdout.write("wrote " + args.out + "\n");
}

// pki csr --key <key> --subject <dn> -- a PKCS#10 certification request over the key's public half,
// which pki.key.publicFromPrivate derives so the caller supplies one file rather than two.
function cmdCsr(args) {
  if (!args.key || !args.subject) return fail(CSR_USAGE);
  var key = _keyArg(args.key);
  return pki.key.publicFromPrivate(key).then(function (spki) {
    var spec = { subject: subjectArg(args.subject), subjectPublicKey: spki };
    // A request asks for extensions through the RFC 2985 extensionRequest attribute, which is what
    // a CA copies into the certificate it issues; a request has no `extensions` of its own.
    var san = sanList(args.san);
    if (san) spec.extensionRequest = { subjectAltName: san };
    return pki.csr.sign(spec, { key: key }, { pem: !!args.pem });
  }).then(function (out) {
    writeOrPrint(args, out);
  }, function (e) { return fail((e.code || "csr/sign-error") + ": " + e.message); });
}

// pki issue -- a certificate over either a supplied key or the public half a request carries.
function cmdIssue(args) {
  var haveKey = !!args.key, haveCsr = !!args.csr;
  if (haveKey === haveCsr) return fail(ISSUE_USAGE);
  if (haveKey && !args.subject) return fail(ISSUE_USAGE);
  // Half an issuer would otherwise take the self-signed path, so a certificate asked to be signed
  // by a CA would come back signed by its own subject key. Refuse instead.
  if (args["issuer-cert"] && !args["issuer-key"]) return fail("issue: --issuer-cert needs --issuer-key");
  if (args["issuer-key"] && !args["issuer-cert"]) return fail("issue: --issuer-key needs --issuer-cert");
  var days = args.days === undefined ? ISSUE_DEFAULT_DAYS : Number(args.days);
  if (!isFinite(days) || days <= 0 || Math.floor(days) !== days) return fail("issue: --days must be a positive whole number of days");

  return Promise.resolve().then(function () {
    if (!haveCsr) {
      var key = _keyArg(args.key);
      var subject = subjectArg(args.subject);
      return pki.key.publicFromPrivate(key).then(function (spki) {
        return { subject: subject, spki: spki, signerKey: key };
      });
    }
    // A request whose signature does not verify proves nothing about who holds the key it carries,
    // so it is verified before anything is certified from it.
    var reqBytes = readForLib(args.csr);
    return pki.csr.verify(reqBytes).then(function (v) {
      if (v !== true && !(v && v.valid === true)) return fail("issue: the request's signature does not verify");
      var req = pki.schema.csr.parse(reqBytes);
      // Both routes hand `subject` over as raw Name DER, which is one of the three forms the
      // builders take. A parse result is not one of them, and neither is a DN string.
      return { subject: req.subject.bytes, spki: req.subjectPublicKeyInfo.bytes, signerKey: null };
    }, function (e) { return fail("issue: the request's signature does not verify (" + (e.code || e.message) + ")"); });
  }).then(function (from) {
    if (from === undefined) return undefined;   // fail() already exited
    var now = new Date();
    var spec = {
      subject: from.subject,
      subjectPublicKey: from.spki,
      notBefore: now,
      notAfter: new Date(now.getTime() + pki.C.TIME.days(days)),
    };
    if (args.serial) spec.serialNumber = BigInt("0x" + String(args.serial).replace(/^0x/, ""));
    var exts = {};
    var san = sanList(args.san);
    if (san) exts.subjectAltName = san;
    if (args.ca) { exts.basicConstraints = { cA: true }; exts.keyUsage = ["keyCertSign", "cRLSign"]; }
    if (Object.keys(exts).length) spec.extensions = exts;
    var issuer = args["issuer-cert"]
      ? { key: _keyArg(args["issuer-key"]), cert: _keyArg(args["issuer-cert"]) }
      : { key: from.signerKey };
    if (issuer.key == null) return fail("issue: --csr needs --issuer-cert and --issuer-key, since a request carries no signing key");
    return pki.x509.sign(spec, issuer, { pem: !!args.pem }).then(function (out) { writeOrPrint(args, out); });
  }).then(undefined, function (e) { return fail((e.code || "x509/sign-error") + ": " + e.message); });
}

var FETCH_USAGE = "usage: pki fetch <https-url> [--anchor <cert>] [--system] [--out <file>] [--der]\n" +
  "  Prints the certificate chain the endpoint presented, leaf first, as PEM.\n" +
  "  This is NOT a verification. The TLS handshake checked that the endpoint's chain builds to\n" +
  "  a configured anchor and that its name matches the URL; it checked no revocation status, no\n" +
  "  policy, and nothing about what the certificate is authorized to do. pki verify is the verb\n" +
  "  that validates a path.\n" +
  "  An anchor is required: --anchor names one, --system uses the platform's store.";

// pki fetch <url> -- the chain a live endpoint presents, read from a TLS handshake that sends no
// request, so nothing reaches the application behind it.
function cmdFetch(args) {
  var url = args._[0];
  if (!url) return fail(FETCH_USAGE);
  var anchors = args.anchor ? [readFileBytes(args.anchor)] : undefined;
  var tlsOpts = {};
  if (anchors) tlsOpts.anchors = anchors;
  if (args.system) tlsOpts.useSystemStore = true;
  return pki.transport.peerChain({ url: url }, { tls: tlsOpts }).then(function (channel) {
    var chain = channel.peerChain || [];
    if (!chain.length) return fail("fetch: the endpoint presented no certificate");
    if (args.der) {
      var der = Buffer.concat(chain);
      writeOrPrint(args, der);
    } else {
      var pem = chain.map(function (d) { return pki.schema.x509.pemEncode(d, "CERTIFICATE"); }).join("");
      writeOrPrint(args, pem);
    }
    // What the handshake established, on stderr so it does not land in a redirected chain file.
    process.stderr.write("pki: " + channel.protocol + " " +
      ((channel.cipher && channel.cipher.name) || "") + "; " + chain.length +
      " certificate(s) presented; the handshake checked the chain against the configured anchor " +
      "and the name in the URL, and checked no revocation status or policy -- pki verify validates a path\n");
  }, function (e) { return fail((e.code || "transport/error") + ": " + e.message); });
}

// pki convert <file> --to der|pem -- transcode between DER and PEM. The input encoding is
// auto-detected; the bytes must be well-formed DER (we never wrap/emit garbage).
function cmdConvert(args) {
  var file = args._[0], to = args.to;
  if (!file) fail("usage: pki convert <file> --to der|pem [--label LABEL]");
  if (to !== "der" && to !== "pem") fail("convert: --to must be 'der' or 'pem'");
  var input = readDer(file);
  try { pki.asn1.decode(input.der); } catch (e) { return fail("input is not well-formed DER: " + (e.code || e.message)); }
  if (to === "der") { process.stdout.write(input.der); return; }
  var label = args.label || input.label || "CERTIFICATE";
  // The armor label must be re-readable by the library's PEM grammar (uppercase A-Z0-9 words,
  // single spaces) -- reject a lowercase/invalid label rather than emit an unparseable file.
  if (!/^[A-Z0-9]+( [A-Z0-9]+)*$/.test(label)) return fail("convert: --label must be an uppercase A-Z0-9 label with single spaces (RFC 7468)");
  var b64 = input.der.toString("base64").replace(/(.{1,64})/g, "$1\n");
  process.stdout.write("-----BEGIN " + label + "-----\n" + b64 + "-----END " + label + "-----\n");
}

// pki verify <cert>... --anchor <cert> -- validate an ordered certification path
// (anchor->target) against a trust anchor via pki.path.validate (RFC 5280 sec. 6.1).
function cmdVerify(args) {
  var certFiles = args._, anchorFile = args.anchor;
  if (!certFiles.length || !anchorFile) fail("usage: pki verify <cert>... --anchor <anchor-cert> [--time ISO]");
  var certs, anchor;
  try { certs = certFiles.map(function (f) { return pki.schema.x509.parse(readForLib(f)); }); }
  catch (e) { return fail("cannot parse a path certificate: " + (e.code || e.message)); }
  try { anchor = pki.schema.x509.parse(readForLib(anchorFile)); }
  catch (e2) { return fail("cannot parse the anchor certificate: " + (e2.code || e2.message)); }
  var time = args.time ? new Date(args.time) : new Date();
  if (isNaN(time.getTime())) fail("verify: --time must be an ISO-8601 date");
  var spki = anchor.subjectPublicKeyInfo;
  return pki.path.validate(certs, {
    time: time,
    trustAnchors: { name: anchor.subject, publicKey: spki.bytes, algorithm: spki.algorithm.oid, parameters: spki.algorithm.parameters },
  }).then(function (res) {
    process.stdout.write(res.valid ? "valid\n" : "invalid\n");
    if (!res.valid) {
      (res.results || []).forEach(function (r, i) {
        (r.checks || []).forEach(function (c) { if (c.ok === false) process.stdout.write("  cert[" + i + "] " + c.code + "\n"); });
      });
    }
    process.exitCode = res.valid ? 0 : 1;   // let Node flush stdout before it exits
  }, function (e) { return fail(e.code + ": " + e.message); });
}

// pki sign <content-file> --cert <cert> --key <key> -- produce a CMS SignedData over the file
// via pki.cms.sign. The signer key is a PKCS#8 DER or PEM private key; the certificate is DER or
// PEM. Output is a DER Buffer (or a PEM block with --pem) to --out or stdout.
function cmdSign(args) {
  var contentFile = args._[0];
  if (!contentFile || !args.cert || !args.key) {
    return fail("usage: pki sign <content-file> --cert <cert> --key <key.pkcs8> [--detached] [--pss] [--digest sha256|sha384|sha512] [--pem] [--out <file>]");
  }
  var content = readFileBytes(contentFile);
  var signer = { cert: _asPemOrDer(readFileBytes(args.cert)), key: _asPemOrDer(readFileBytes(args.key)) };
  if (args.pss) signer.pss = true;
  if (args.digest) signer.digestAlgorithm = args.digest;
  return pki.cms.sign(content, signer, { detached: !!args.detached, pem: !!args.pem }).then(function (out) {
    if (args.out) { try { fs.writeFileSync(args.out, out); } catch (e) { return fail("cannot write " + args.out + ": " + e.message); } }
    else { process.stdout.write(out); }   // process.exitCode (0) lets Node flush a piped stdout
  }, function (e) { return fail((e.code || "cms/sign-error") + ": " + e.message); });
}
// A PEM file (its first byte is '-') is passed to pki.cms.sign as a string; a DER file as its
// Buffer. cms.sign accepts either for the certificate and needs a string for a PEM private key.
function _asPemOrDer(buf) { return buf[0] === 0x2d ? buf.toString("latin1") : buf; }

var USAGE = "usage: pki <version|oid|parse|inspect|keygen|csr|issue|fetch|lint|convert|verify|sign> [args]\n";

function main(argv) {
  var cmd = argv[0];
  switch (cmd) {
    case "version": case "--version": case "-v": return cmdVersion();
    case "oid":     return cmdOid(argv[1]);
    case "parse":   return cmdParse(argv[1]);
    case "inspect": return cmdInspect(parseArgs(argv.slice(1)));
    case "keygen":  return cmdKeygen(parseArgs(argv.slice(1)));
    case "csr":     return cmdCsr(parseArgs(argv.slice(1)));
    case "issue":   return cmdIssue(parseArgs(argv.slice(1)));
    case "fetch":   return cmdFetch(parseArgs(argv.slice(1)));
    case "lint":    return cmdLint(parseArgs(argv.slice(1)));
    case "convert": return cmdConvert(parseArgs(argv.slice(1)));
    case "verify":  return cmdVerify(parseArgs(argv.slice(1)));
    case "sign":    return cmdSign(parseArgs(argv.slice(1)));
    case undefined: case "help": case "--help": case "-h":
      process.stdout.write(USAGE);
      return;
    default:
      return fail("unknown command: " + cmd);
  }
}

Promise.resolve(main(process.argv.slice(2))).catch(function (e) { fail(e && (e.stack || e.message) || String(e)); });
