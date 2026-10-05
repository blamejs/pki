#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * pki: the command-line front-end for @blamejs/pki.
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
 * arguments (the entry-point tier, where bad input exits non-zero with a message) and never does
 * anything the public API cannot. inspect / lint / convert / verify / sign compose pki.inspect,
 * pki.lint, the per-format PEM codecs, pki.path.validate, and pki.cms.sign respectively.
 */

var fs  = require("node:fs");
var pki = require("../index.js");

// One line stays one line. A path comes from the command line, and a carriage return or newline in one
// would end the line early and put whatever follows it where an operator reads a report of the tool's
// own, so those two bytes are shown rather than obeyed. Shared by every report: fifteen `fail` call
// sites interpolate a caller-supplied path, and escaping only the exit-handler's reports left those
// printing the raw byte. Measured: `keygen --pub "nl\na.pub"` over an existing file reported across two
// lines, the second reading as a line of this tool's own output.
function _oneLine(message) {
  var text = String(message);
  var one = "";
  for (var i = 0; i < text.length; i++) {
    var c = text.charCodeAt(i);
    // TWO hex digits. `(0x0a).toString(16)` is "a", so a one-digit escape ran straight into the next
    // character of the path: a newline followed by "a" printed as "\xaa", which reads as an escape of
    // one byte while standing for two. The reader cannot tell those apart, so the width is fixed.
    one += (c === 0x0a || c === 0x0d) ? (c === 0x0a ? "\\x0a" : "\\x0d") : text.charAt(i);
  }
  return one;
}

function fail(msg) {
  process.stderr.write("pki: " + _oneLine(msg) + "\n");
  process.exit(1);
}

// A stdout that cannot be written -- a closed descriptor, a full pipe -- raises an `error` event on
// the stream rather than throwing where the write was called, and with nothing listening Node ended
// the process with its own stack trace. Two things follow. The message an operator gets is a
// `node:events` dump instead of a `pki:` line, and for a verb whose product is a FILE the exit code
// said failure about work that had completed: `keygen` wrote the key, could not print the line saying
// so, and exited non-zero with the key on disk, which is indistinguishable from the failure that
// leaves a secret behind.
//
// So the product's location decides the exit code. `wroteToDisk` is set by a verb once its output is
// on disk rather than on stdout; for every other verb stdout IS the product and a failure to write it
// is the command failing.
var wroteToDisk = false;
function _onOutputError(stream, e) {
  if (stream !== "stderr") {
    try {
      process.stderr.write("pki: " + stream + " could not be written (" + e.message + ")" +
        (wroteToDisk ? "; the output was written to disk and is intact" : "") + "\n");
    } catch (_e) { /* allow:swallow-unverified nothing can be reported; the exit code is the record */ }
  }
  process.exit(wroteToDisk ? 0 : 1);
}
process.stdout.on("error", function (e) { _onOutputError("stdout", e); });
process.stderr.on("error", function (e) { _onOutputError("stderr", e); });

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

// A verb taking a bare positional answers a missing argument with its own usage line. An explicit
// `--help` never reaches here: `main` answers it before the verb runs, so an argument that is absent
// is the only case left.
function usageOrArg(arg, usage) {
  if (!arg) return fail(usage);
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

var VERSION_USAGE = "usage: pki version\n" +
  "  Prints the installed @blamejs/pki version. --version and -v are the same verb.";
function cmdVersion() {
  process.stdout.write("@blamejs/pki v" + pki.version + "\n");
}

var OID_USAGE = "usage: pki oid <dotted|name>";
function cmdOid(arg) {
  usageOrArg(arg, OID_USAGE);
  if (/^\d+(\.\d+)+$/.test(arg)) {
    var name = pki.oid.name(arg);
    process.stdout.write((name || "(unregistered)") + "\n");
  } else {
    var dotted = pki.oid.byName(arg);
    if (!dotted) fail("unknown OID name: " + arg);
    process.stdout.write(dotted + "\n");
  }
}

var PARSE_USAGE = "usage: pki parse <cert.pem|cert.der>";
function cmdParse(file) {
  usageOrArg(file, PARSE_USAGE);
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
var INSPECT_USAGE = "usage: pki inspect <file.pem|file.der> [--asn1]";
function cmdInspect(args) {
  var file = args._[0];
  if (!file) fail(INSPECT_USAGE);
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
  // Set the exit CODE and let Node drain: process.exit() can truncate a buffered stdout
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

// The files THIS invocation created, so a run that does not complete removes its own residue and
// nothing else. A pre-existing file is never listed and so is never removed: the failure an operator
// is most likely to hit is a name already taken, and destroying what is there would be the very thing
// refusing to write over it prevents.
//
// It hangs off `exit` rather than off each failure site because `fail` ends the process where it is
// called, so there is no scope around the sequence to clean up in. Reserving the public name before
// writing the private key fixed one residue and created another: a run that failed on `--out` left
// the empty public file behind and the corrected retry then refused for THAT name instead.
// Each entry records what the file looked like when this run created it, so cleanup can tell its own
// file from one that replaced it. Without that, a path swapped between the create and the cleanup had
// the REPLACEMENT deleted, which turns a tidy-up into data loss. The window is not closed by this,
// there being no unlink-by-handle to use, but a file whose size or timestamp has changed is left
// where it is and named.
var createdFiles = [];
// Two separate questions, recorded at two different moments.
//
// IDENTITY (`ino`/`dev`) is taken from the creating descriptor, at the moment the name becomes ours and
// before any content goes into it, so the record can tell our file from one that replaced it even when
// the write that followed never finished. Recorded only once the content was in, a write that failed
// left an identity-free record, and an identity-free record was deleted with no comparison at all: a
// replacement arriving in that window was removed. An unidentifiable file is exactly the one not to
// delete blindly.
//
// CONTENT (`size`/`mtimeMs`) is recorded only once a write returns, because that is the only point at
// which what is on disk is what this run meant to put there. A record with no content figure is a file
// this run created and did not finish, which is removed when its identity still matches: leaving a
// partially written private key behind is the residue the record exists to clear.
//
// `nlink` is the third: unlinking a path whose content has another link removes the name and keeps the
// content, so a file linked since this run created it is left where it is and named rather than
// half-removed. Where a platform reports no inode or no link count the figures compare equal and the
// size and timestamp carry the comparison alone, which cannot distinguish a replacement that matches
// both.
function _claimCreated(file, fd) {
  var rec = { path: file, size: null, mtimeMs: null, ino: null, dev: null, nlink: null };
  _identify(rec, fd);
  createdFiles.push(rec);
  return rec;
}
// Both are called with the descriptor still OPEN, so what they record is of the file this run holds
// rather than of whatever occupies the path afterwards. Taken by path after the close, a writer that
// replaced the file in between had its replacement's size and timestamp adopted as this run's own, and
// cleanup then deleted that replacement: the comparison meant to prevent exactly that was reading the
// wrong file.
function _identify(rec, fd) {
  try {
    var st = fs.fstatSync(fd);
    rec.ino = st.ino; rec.dev = st.dev; rec.nlink = st.nlink;
  } catch (_e) { /* allow:swallow-unverified unstattable; the record carries no identity and is kept */ }
}
function _sealCreated(rec, fd) {
  try {
    var st = fs.fstatSync(fd);
    rec.size = st.size; rec.mtimeMs = st.mtimeMs;
    rec.ino = st.ino; rec.dev = st.dev; rec.nlink = st.nlink;
  } catch (_e) { /* allow:swallow-unverified unstattable; the claim-time identity stands */ }
}
// One line about one file, on the stream that reports them. A stream that cannot be written carries no
// report, and that is the end of it: the file is intact either way, which is the half that matters, and
// there is nowhere else to say so from inside an exit handler.
function _say(message) {
  // Through the same escaper every report uses, so a path with a newline in it cannot forge a line
  // here either.
  try { process.stderr.write("pki: " + _oneLine(message) + "\n"); }
  catch (_e) { /* allow:swallow-unverified nothing can be reported; the file is untouched */ }
}
process.on("exit", function (code) {
  // `wroteToDisk` means the product is COMPLETE on disk, and then no exit path may remove it. A
  // synchronous throw out of the final status write reaches `fail`, which exits non-zero, and cleanup
  // keyed on the exit code alone deleted a key that had been written exactly as asked.
  if (code === 0 || wroteToDisk) return;
  for (var i = 0; i < createdFiles.length; i++) {
    var rec = createdFiles[i];
    var now = null, statErr = null;
    try { now = fs.statSync(rec.path); }
    catch (e0) { statErr = e0; }
    if (statErr !== null) {
      // Anything but ENOENT means the path could not be looked at, which is not the same as the file
      // being gone: a file nobody could look at is one nobody removed, and that outcome used to be
      // passed over in silence. ENOENT means nothing is there NOW, which this run did not necessarily
      // do: a file it created and something else renamed leaves the same empty path, and the bytes are
      // then somewhere an operator has not been told about.
      if (statErr.code !== "ENOENT") {
        _say(rec.path + " was created by this run and could not be examined, so it was left in " +
          "place (" + statErr.message + ")");
      } else if (rec.ino !== null) {
        _say(rec.path + " was created by this run and is no longer there, so its content is " +
          "wherever it was moved to");
      }
      continue;
    }
    // A different inode under the same name is a different file, whatever its size and timestamp say,
    // so that comparison runs first where the platform reports one.
    var known = rec.ino !== null && rec.ino !== 0 && now.ino !== 0;
    var leave = null;
    if (known && (now.ino !== rec.ino || now.dev !== rec.dev)) {
      leave = " was replaced since this run created it and was left in place";
    } else if (now.nlink > 1) {
      // An exclusive create gives a file ONE name, so a second one was added by somebody else, and
      // unlinking this name would remove the name and leave the content. Asked of what is on disk NOW
      // rather than against the count this run recorded: recorded, a link added before the record was
      // taken and removed afterwards made the count go DOWN, and a comparison looking for growth let
      // the unlink through while another name still held the bytes.
      leave = " has more than one link, so removing this name would leave the content, and it was " +
        "left in place";
    } else if (rec.size !== null && (now.size !== rec.size || now.mtimeMs !== rec.mtimeMs)) {
      leave = " changed since this run created it and was left in place";
    } else if (!known && rec.size === null) {
      // No identity from the platform and no completed write: the file at this path cannot be told
      // from one that replaced it, and deleting on a guess is the one outcome that cannot be undone.
      leave = " was created by this run and cannot be identified on this filesystem, so it was " +
        "left in place and is yours to remove";
    }
    if (leave !== null) { _say(rec.path + leave); continue; }
    try { fs.unlinkSync(rec.path); }
    catch (e) {
      _say(rec.path + " was created by this run and could not be removed (" + e.message + ")");
    }
  }
});

// Write a file that must not exist yet, with its mode set in the call that creates it: a chmod
// after the write leaves a window where the key is readable by anyone who can open the file.
// Create a file that must not exist yet and write it through the DESCRIPTOR the create returned. Four
// rules meet here and each of them was learned the hard way:
//
//   - the mode goes in the creating call, because a chmod afterwards leaves a window where the key is
//     readable by anyone who can open the file;
//   - only the descriptor is written through. Closing the exclusive create and reopening the PATH let
//     the reservation be replaced in between, and the write would then follow a replacement symlink or
//     truncate a replacement file, which is the no-overwrite guarantee defeating itself;
//   - the claim is recorded BEFORE any content, and it carries the new file's identity from the
//     creating descriptor, so a write that fails part way through still leaves a file the cleanup can
//     recognize as its own and remove;
//   - the descriptor is closed on every path before the cleanup can run, because Windows will not
//     unlink a file something still has open.
function writeNewFile(file, bytes, mode) {
  var fd;
  try { fd = fs.openSync(file, "wx", mode); }
  catch (e) {
    if (e.code === "EEXIST") return fail(file + " already exists, and a key is never written over one");
    return fail("cannot write " + file + ": " + e.message);
  }
  return _writeThrough(fd, file, bytes);
}

// The content, the claim, the seal and the close, for a descriptor the caller has already created.
function _writeThrough(fd, file, bytes) {
  var rec = _claimCreated(file, fd);
  var err = null;
  try { fs.writeFileSync(fd, bytes); }
  catch (e2) { err = e2; }
  // Sealed BEFORE the close, while the descriptor still names the file this run wrote.
  if (err === null) _sealCreated(rec, fd);
  try { fs.closeSync(fd); }
  catch (e3) { if (err === null) err = e3; }
  if (err !== null) return fail("cannot write " + file + ": " + err.message);
}

// An output file for the verbs whose product is not a key: `csr`, `issue`, `fetch` and `sign` with
// `--out`. Overwriting a path that is already taken is what those verbs have always done, and a
// certificate or a request is not a secret whose only copy gets destroyed, so that stays. What the
// plain write did not do is let the cleanup know: a write that failed part way left a file this run
// had just created with nobody tracking it, which is the residue the record exists to clear. So a
// path that does NOT exist is created exclusively and written through its descriptor like a key is,
// and one that DOES is overwritten with no record kept, because a file this run did not create is
// never one it removes.
function writeOutputFile(file, bytes) {
  // Two attempts, because "the path is taken" and "the path is free" are answers about the moment they
  // were given. The overwrite arm opens the path WITHOUT permission to create it, so a path that stops
  // existing between the two calls comes back as ENOENT and is retried as the exclusive create it now
  // is. Written as a plain write, that window created a file this run owned with nobody tracking it.
  for (var attempt = 0; attempt < 2; attempt++) {
    var fd;
    try { fd = fs.openSync(file, "wx"); }
    catch (e) {
      if (e.code !== "EEXIST") return fail("cannot write " + file + ": " + e.message);
      var efd;
      /** WRITE-ONLY, and without permission to create. A read-write open makes this process its own
       * reader on a FIFO, so the open succeeds with nobody listening and the bytes go into a pipe no
       * one drains: a small result is written, the descriptor closes, the command reports success and
       * the output is gone, while a larger one blocks. A write-only open waits for a reader, which is
       * what a caller naming a FIFO asked for. `O_TRUNC` is NOT set here: it is what made this open
       * EINVAL on Windows, not `O_WRONLY`, and a regular file is truncated through its descriptor
       * below where that is meaningful. */
      try { efd = fs.openSync(file, fs.constants.O_WRONLY); }
      catch (e2) {
        if (e2.code === "ENOENT") continue;
        /** A destination that refuses a write-only open without create is written by name, as every one
         * of these verbs did before, and nothing is tracked for it because this run did not create it
         * and will never remove it. A regular file always takes the descriptor path above. */
        try { fs.writeFileSync(file, bytes); }
        catch (e3) { return fail("cannot write " + file + ": " + e3.message); }
        return undefined;
      }
      return _overwriteThrough(efd, file, bytes);
    }
    return _writeThrough(fd, file, bytes);
  }
  return fail("cannot write " + file + ": the path kept appearing and disappearing while it was " +
    "being opened");
}

// The content of a file that was already there, written through the descriptor the open returned
// rather than by name, so what is truncated and what is written are the same file. A failure here has
// destroyed what was there, and the message says so: the caller asked for an overwrite and got a
// partial one, which is the one outcome a bare "cannot write" would not tell them.
function _overwriteThrough(fd, file, bytes) {
  var err = null;
  try {
    // Truncated only where there is something to truncate: `ftruncate` refuses a character device or a
    // FIFO, and an operator writes to `/dev/null`. Those hold no previous content for a short write to
    // leave behind, so skipping it there costs nothing.
    if (fs.fstatSync(fd).isFile()) fs.ftruncateSync(fd, 0);
    // `writeFileSync` on the descriptor, not `writeSync`: a single write can return a SHORT count
    // without throwing, and a caller that ignores the count closes a half-written file and reports
    // success. This one owns the loop until every byte is out. The descriptor sits at offset zero and
    // the truncate does not move it, so the bytes land at the front.
    fs.writeFileSync(fd, bytes);
  } catch (e) { err = e; }
  try { fs.closeSync(fd); }
  catch (e2) { if (err === null) err = e2; }
  if (err !== null) {
    return fail("cannot write " + file + ": " + err.message + "; the file that was at that path has " +
      "been overwritten and what is there now is incomplete");
  }
  return undefined;
}

// pki keygen --out <file> -- generate a key pair and write the private key to a file. The public
// half goes to --pub when asked for, so an operator sending a public key does not have to hand over
// a file that also holds the private one.
function cmdKeygen(args) {
  if (!args.out) return fail(KEYGEN_USAGE);
  // One path for both halves would put the private key at the name the public one was asked for. The
  // exclusive create refuses the second write, so the run already failed; refusing it here says why,
  // before a key is generated, rather than reporting the destination as taken by something else.
  if (args.pub && args.pub === args.out) {
    return fail("--out and --pub name the same file, and the public half is not written where the " +
      "private key goes");
  }
  var alg = args.alg || KEYGEN_DEFAULT_ALG;
  return pki.key.generate(alg).then(function (pair) {
    return Promise.all([pki.key.export(pair.privateKey), pki.key.export(pair.publicKey)]);
  }, function (e) {
    return fail("keygen: cannot generate " + alg + ": " + (e.code || e.message));
  }).then(function (both) {
    if (both === undefined) return undefined;   // fail() already exited
    var privDer = both[0], pubDer = both[1];
    var priv = args.pem ? pki.schema.pkcs8.pemEncode(privDer, "PRIVATE KEY") : privDer;
    // Both destinations are taken before either key is written. Writing the private half first left a
    // freshly generated secret at --out whenever the public write failed, with the command reporting
    // failure, and the retry an operator would run next then refused because --out existed. The public
    // NAME is claimed first, by the same exclusive create that refuses an existing file, so a
    // collision there is found before any key reaches the disk.
    // The PUBLIC half goes first, which is what secures its name before any private key reaches the
    // disk while still writing each file through its own descriptor. Writing the private key first
    // left a freshly generated secret at --out whenever the public write failed, and reserving the
    // public name as an empty file to be filled later meant reopening a path, which is the race above.
    // A failure on the private key now leaves a complete PUBLIC file, and the exit handler removes it.
    // There is no cleanup written by hand here: every failure exits non-zero and the handler removes
    // what this run created, checking each file is still the one it wrote.
    if (args.pub) writeNewFile(args.pub, args.pem ? _spkiPem(pubDer) : pubDer, undefined);
    writeNewFile(args.out, priv, KEY_FILE_MODE);
    // The product of this verb is the FILE, not the line that says so, so a stdout that cannot be
    // written does not undo a key that is already on disk. See `wroteToDisk` above for what that
    // changes: the message and the exit code, not the key.
    wroteToDisk = true;
    // Through the same escaper the refusals use. A SUCCESS line names the caller's paths too, so a
    // newline in one ended the line early here as well, and this one goes to stdout where a script
    // reading the tool's output is most likely to be parsing it.
    process.stdout.write(_oneLine("wrote " + alg + " private key to " + args.out +
      (args.pub ? " and its public key to " + args.pub : "")) + "\n");
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
  "                 [--copy-requested-san] [--ignore-requested-extensions]\n" +
  "  With no issuer the certificate is self-signed by --key. An issuer needs both halves: a\n" +
  "  certificate with no key, or a key with no certificate, is refused rather than self-signed.\n" +
  "  A request asks for extensions, and what a CA issues is its own decision (RFC 2985 sec. 5.4.2),\n" +
  "  so a request that asks for any is refused until one of these two says what to do with them:\n" +
  "  --copy-requested-san writes the requested subjectAltName into the certificate, and\n" +
  "  --ignore-requested-extensions issues without what the request asked for.\n" +
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

// The GeneralName forms `--copy-requested-san` writes into a certificate, by context tag. A decoded
// name of one of these carries the value the builder takes for that form: a string for the three
// text forms, a 4- or 16-octet Buffer for an address. directoryName [4] and otherName [0] are not
// here, so a request asking for one is named and refused rather than dropped from the copy.
var SAN_FORM_FOR_TAG = { 1: "rfc822Name", 2: "dNSName", 6: "uniformResourceIdentifier", 7: "iPAddress" };
// A requested subjectAltName as the names the certificate builder takes. Every name is converted,
// and a form with no conversion stops the issuance: a certificate carrying SOME of the names a
// request asked for is a different certificate from the one it asked for, and the operator asked for
// the copy.
// Whether the Name the certificate will carry is empty, read the way the certificate builder reads
// it: an encoded Name holding no RDNs. The builder takes the subjectAltName's criticality from that
// same answer, so the two agree on which form is being issued.
function subjectNameIsEmpty(subject) {
  if (!Buffer.isBuffer(subject)) return false;
  try { return pki.asn1.decode(subject).children.length === 0; }
  catch (_e) { return false; }
}

function requestedSanNames(rows, subject) {
  var san = rows.filter(function (r) { return r.name === "subjectAltName"; });
  if (!san.length) return undefined;
  if (san[0].state !== "decoded") {
    return fail("issue: the request's subjectAltName cannot be read (" + (san[0].code || san[0].state) +
      "), so --copy-requested-san has nothing to copy");
  }
  // RFC 5280 sec. 4.2.1.6 asks for a critical subjectAltName where the subject is empty and a
  // non-critical one beside a subject, and the certificate builder writes whichever the subject it
  // encodes calls for. So a critical request is answered as it was made when the subject is empty,
  // which is the only conforming shape for a SAN-only request, and loses its criticality only beside
  // a non-empty subject. That is the case this refuses.
  if (san[0].critical === true && !subjectNameIsEmpty(subject)) {
    return fail("issue: the request asks for a CRITICAL subjectAltName, which RFC 5280 sec. 4.2.1.6 " +
      "asks for only where the subject is empty, and this request carries a subject; beside a " +
      "subject this verb writes a non-critical subjectAltName, so copying it would answer a " +
      "different request than the one that was made. State the names with --san, or build the " +
      "certificate through pki.x509.sign, whose pre-encoded extensions array writes the " +
      "criticality it is given");
  }
  var names = (san[0].decoded && san[0].decoded.names) || [];
  var out = [], unconvertible = [];
  for (var i = 0; i < names.length; i++) {
    var form = Object.prototype.hasOwnProperty.call(SAN_FORM_FOR_TAG, names[i].tagNumber)
      ? SAN_FORM_FOR_TAG[names[i].tagNumber] : null;
    if (form === null) { unconvertible.push("[" + names[i].tagNumber + "]"); continue; }
    var entry = {};
    entry[form] = names[i].value;
    out.push(entry);
  }
  if (unconvertible.length) {
    return fail("issue: the request's subjectAltName holds " + unconvertible.length + " name" +
      (unconvertible.length === 1 ? "" : "s") + " of a form --copy-requested-san does not write (" +
      unconvertible.join(", ") + "); state the names with --san instead");
  }
  if (!out.length) return fail("issue: the request's subjectAltName holds no names");
  return out;
}

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
  writeOutputFile(args.out, bytes);
  // The product is the FILE here too, for every verb that routes through this: `csr`, `issue` and
  // `fetch` with `--out`. The rule arrived with `keygen` and applied to keygen alone, so a broken
  // stdout made these exit non-zero over a file that was already written, which is the same
  // contradiction one verb further on.
  wroteToDisk = true;
  process.stdout.write(_oneLine("wrote " + args.out) + "\n");
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
  // Both flags answer a question only a request asks, so on the --key route neither has anything to
  // decide, and a flag that silently does nothing reads as one that was honored.
  if (!haveCsr && (args["copy-requested-san"] || args["ignore-requested-extensions"])) {
    return fail("issue: --copy-requested-san and --ignore-requested-extensions answer what a request " +
      "asks for, so they need --csr");
  }
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
      // What the request ASKS FOR is read here and answered below. RFC 2985 sec. 5.4.2 leaves to the
      // CA which requested extensions to honor, so neither answer is taken by default: a copy would
      // let the requester write its own names into the certificate, and a drop would issue a
      // certificate the request did not ask for while reporting success.
      var rows = pki.schema.csr.decodeExtensions(reqBytes);
      // Both routes hand `subject` over as raw Name DER, which is one of the three forms the
      // builders take. A parse result is not one of them, and neither is a DN string.
      return { subject: req.subject.bytes, spki: req.subjectPublicKeyInfo.bytes, signerKey: null,
        requested: rows };
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
    // Every extension the request asked for has to be answered, and the answer is the operator's.
    // What neither flag accounts for is named and refused: the certificate otherwise comes back
    // reporting success while carrying less than was asked for, which is the case an operator finds
    // when a name it never checked turns out to be missing.
    var requested = (from.requested || []).map(function (r) { return r.name || r.oid; });
    var unanswered = requested.filter(function (n) {
      if (args["ignore-requested-extensions"]) return false;
      return !(n === "subjectAltName" && args["copy-requested-san"]);
    });
    if (unanswered.length) {
      return fail("issue: the request asks for " + unanswered.join(", ") + ", and what a CA issues " +
        "is its own decision (RFC 2985 sec. 5.4.2). Pass --copy-requested-san to write the requested " +
        "subjectAltName, or --ignore-requested-extensions to issue without what the request asked for");
    }
    if (args["copy-requested-san"]) {
      if (san) return fail("issue: --san and --copy-requested-san both name the subjectAltName; pass one");
      san = requestedSanNames(from.requested || [], from.subject);
      if (san === undefined) return fail("issue: --copy-requested-san was passed and the request asks for no subjectAltName");
    }
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
  "  Prints the certificate chain the TLS session resolved, leaf first, as PEM. The chain is\n" +
  "  completed from the anchors in scope, so an entry above the leaf may come from a configured\n" +
  "  anchor rather than from the endpoint; the leaf is the one the endpoint certainly sent.\n" +
  "  This is NOT a verification. The TLS handshake checked that the endpoint's chain builds to\n" +
  "  a configured anchor and that its name matches the URL; it checked no revocation status, no\n" +
  "  policy, and nothing about what the certificate is authorized to do. pki verify is the verb\n" +
  "  that validates a path.\n" +
  "  An anchor is required: --anchor names one, --system uses the platform's store.\n" +
  "  --der writes one certificate. A chain of several is refused under it, several concatenated DER\n" +
  "  certificates not being a DER document that pki parse can read back.";

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
      // Concatenating several certificates produces several top-level DER values with nothing framing
      // them, which is not a DER document: `pki parse` and `pki convert` reject it with `x509/bad-der`,
      // so the file written was one this tool could not read back. One certificate is a document and is
      // written as it was; more than one is refused, naming the two forms that do hold a chain.
      if (chain.length > 1) {
        return fail("fetch: --der writes one certificate, and this chain has " + chain.length +
          ". Several DER certificates concatenated are not a DER document, so `pki parse` and " +
          "`pki convert` reject the result. Omit --der for the chain as PEM, whose first block is the " +
          "leaf, and convert that one block if you need its DER");
      }
      writeOrPrint(args, chain[0]);
    } else {
      var pem = chain.map(function (d) { return pki.schema.x509.pemEncode(d, "CERTIFICATE"); }).join("");
      writeOrPrint(args, pem);
    }
    // What the handshake established, on stderr so it does not land in a redirected chain file.
    process.stderr.write("pki: " + channel.protocol + " " +
      ((channel.cipher && channel.cipher.name) || "") + "; " + chain.length +
      " certificate(s) in the resolved chain, which may include one completed from a configured " +
      "anchor rather than sent by the endpoint; the handshake checked the chain against the configured anchor " +
      "and the name in the URL, and checked no revocation status or policy -- pki verify validates a path\n");
  }, function (e) { return fail((e.code || "transport/error") + ": " + e.message); });
}

// pki convert <file> --to der|pem -- transcode between DER and PEM. The input encoding is
// auto-detected; the bytes must be well-formed DER (we never wrap/emit garbage).
var CONVERT_USAGE = "usage: pki convert <file> --to der|pem [--label LABEL]";
function cmdConvert(args) {
  var file = args._[0], to = args.to;
  if (!file) fail(CONVERT_USAGE);
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
var VERIFY_USAGE = "usage: pki verify <cert>... --anchor <anchor-cert> [--time ISO]";
function cmdVerify(args) {
  var certFiles = args._, anchorFile = args.anchor;
  if (!certFiles.length || !anchorFile) fail(VERIFY_USAGE);
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
var SIGN_USAGE = "usage: pki sign <content-file> --cert <cert> --key <key.pkcs8> [--detached] [--pss] " +
  "[--digest sha256|sha384|sha512] [--pem] [--out <file>]";
function cmdSign(args) {
  var contentFile = args._[0];
  if (!contentFile || !args.cert || !args.key) return fail(SIGN_USAGE);
  var content = readFileBytes(contentFile);
  var signer = { cert: _asPemOrDer(readFileBytes(args.cert)), key: _asPemOrDer(readFileBytes(args.key)) };
  if (args.pss) signer.pss = true;
  if (args.digest) signer.digestAlgorithm = args.digest;
  return pki.cms.sign(content, signer, { detached: !!args.detached, pem: !!args.pem }).then(function (out) {
    if (args.out) { writeOutputFile(args.out, out); }
    else { process.stdout.write(out); }   // process.exitCode (0) lets Node flush a piped stdout
  }, function (e) { return fail((e.code || "cms/sign-error") + ": " + e.message); });
}
// A PEM file (its first byte is '-') is passed to pki.cms.sign as a string; a DER file as its
// Buffer. cms.sign accepts either for the certificate and needs a string for a PEM private key.
function _asPemOrDer(buf) { return buf[0] === 0x2d ? buf.toString("latin1") : buf; }

var USAGE = "usage: pki <version|oid|parse|inspect|keygen|csr|issue|fetch|lint|convert|verify|sign> [args]\n";

// The usage line each verb prints, by verb. `main` answers `pki <verb> --help` from this table, so
// every verb answers help the way `pki --help` does: on stdout, with a zero exit code. A verb reached
// help through its own missing-argument check before, which calls `fail`, and a script could not tell
// `pki csr --help` from a csr that failed to run.
var VERB_USAGE = {
  version: VERSION_USAGE, "--version": VERSION_USAGE, "-v": VERSION_USAGE,
  oid: OID_USAGE, parse: PARSE_USAGE, inspect: INSPECT_USAGE, keygen: KEYGEN_USAGE,
  csr: CSR_USAGE, issue: ISSUE_USAGE, fetch: FETCH_USAGE, lint: LINT_USAGE,
  convert: CONVERT_USAGE, verify: VERIFY_USAGE, sign: SIGN_USAGE,
};
// Own properties only, so a verb name that happens to be a name on Object.prototype does not read as
// a verb the table carries.
function _usageFor(cmd) {
  return Object.prototype.hasOwnProperty.call(VERB_USAGE, cmd) ? VERB_USAGE[cmd] : null;
}
// Asked of the operator's own arguments, not of the parsed flags: `parseArgs` fails on a value flag
// whose value is missing, so `pki csr --key --help` would exit non-zero before anything looked for
// help, and `pki oid` never parses its argument at all.
function _asksHelp(rest) {
  for (var i = 0; i < rest.length; i++) if (rest[i] === "--help" || rest[i] === "-h") return true;
  return false;
}

function main(argv) {
  var cmd = argv[0];
  var verbUsage = _usageFor(cmd);
  if (verbUsage !== null && _asksHelp(argv.slice(1))) {
    // Written, not exited through: `process.exit` can truncate a buffered stdout write to a pipe, and
    // the exit code is already 0.
    process.stdout.write(verbUsage.charAt(verbUsage.length - 1) === "\n" ? verbUsage : verbUsage + "\n");
    return;
  }
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
