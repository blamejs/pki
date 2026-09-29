// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.inspect.asn1: the structural TLV dump, shaped after
 * `openssl asn1parse`. The subject is a renderer over byte offsets, so the
 * control vector's offsets, depths, header lengths and content lengths are
 * hand-computed from a literal DER string and compared against a literal
 * expected report, not against numbers read back from the code under test.
 *
 * Two routes reach a report: a strict DER decode, and a tolerant header walk
 * when that decode refuses. The second is the half that rots unseen, so every
 * refusal class the first produces has a vector that drives it: an indefinite
 * length, a segmented string, a non-minimal length, a truncation, trailing
 * bytes, and nesting past the depth cap.
 */

var pki = require("../../index.js");
var helpers = require("../helpers");
var check = helpers.check;
var b = pki.asn1.build;
var cp = require("node:child_process");
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

function codeOf(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code || e.constructor.name; } }
function lines(report) { return report.split("\n"); }
function hasLine(report, want) { return lines(report).indexOf(want) !== -1; }
function lineWith(report, needle) {
  var ls = lines(report);
  for (var i = 0; i < ls.length; i++) if (ls[i].indexOf(needle) !== -1) return ls[i];
  return null;
}

/** The column layout, written once here so a per-tag vector states the four measured
 *  numbers and the rendered value and nothing about spacing. The control vector below
 *  does not use it: it compares against a literal report so the layout itself is pinned. */
var NAME_COLUMN = 26;
function padLeft(s, w) { return s.length >= w ? s : " ".repeat(w - s.length) + s; }
function line(offset, depth, hl, len, form, name, value) {
  var head = padLeft(String(offset), 5) + ":d=" + depth + "  hl=" + hl +
    " l=" + padLeft(String(len), 4) + " " + form + ":";
  var field = " ".repeat(depth) + name;
  if (value === null) return head + " " + field;
  var column = field.length + 1 > NAME_COLUMN ? field + " " : field + " ".repeat(NAME_COLUMN - field.length);
  return head + " " + column + ":" + value;
}

/* ------------------------------------------------------------------ *
 * The hand-computed control.
 *
 * SEQUENCE { INTEGER 1, OBJECT IDENTIFIER 2.5.4.3, SEQUENCE { BOOLEAN TRUE, NULL } }
 *
 *   30 0f                       offset  0   hl 2   l 15   constructed
 *      02 01 01                 offset  2   hl 2   l  1   INTEGER 1
 *      06 03 55 04 03           offset  5   hl 2   l  3   OID 2.5.4.3
 *      30 05                    offset 10   hl 2   l  5   constructed
 *         01 01 ff              offset 12   hl 2   l  1   BOOLEAN 0xff
 *         05 00                 offset 15   hl 2   l  0   NULL
 *
 * Seventeen bytes in all: 2 + 3 + 5 + 2 + 3 + 2.
 * ------------------------------------------------------------------ */
var CONTROL_HEX = "300f020101060355040330050101ff0500";
var CONTROL = Buffer.from(CONTROL_HEX, "hex");
var CONTROL_REPORT = [
  "ASN.1 structure: 17 bytes, decoded as DER",
  "    0:d=0  hl=2 l=  15 cons: SEQUENCE",
  "    2:d=1  hl=2 l=   1 prim:  INTEGER                  :1",
  "    5:d=1  hl=2 l=   3 prim:  OBJECT IDENTIFIER        :2.5.4.3 (commonName)",
  "   10:d=1  hl=2 l=   5 cons:  SEQUENCE",
  "   12:d=2  hl=2 l=   1 prim:   BOOLEAN                 :TRUE",
  "   15:d=2  hl=2 l=   0 prim:   NULL",
  "Complete: the structure ends at offset 17, the end of the input.",
].join("\n");

function runControl() {
  check("A1: CONTROL_HEX is the 17 bytes the comment adds up, so the vector's arithmetic holds",
    CONTROL.length === 17);
  check("A2: the control renders exactly the hand-computed offsets, depths and lengths",
    pki.inspect.asn1(CONTROL) === CONTROL_REPORT);
  check("A3: the same structure through the builder renders the same report",
    pki.inspect.asn1(b.sequence([b.integer(1), b.oid("2.5.4.3"),
      b.sequence([b.boolean(true), b.nullValue()])])) === CONTROL_REPORT);
  check("A4: a PEM block of the same bytes renders the same report",
    pki.inspect.asn1("-----BEGIN ANY-----\n" + CONTROL.toString("base64") +
      "\n-----END ANY-----\n") === CONTROL_REPORT);
  check("A5: a Uint8Array of the same bytes renders the same report",
    pki.inspect.asn1(new Uint8Array(CONTROL)) === CONTROL_REPORT);
  /* The two reports pki.inspect.asn1's own docstring prints. A documented example is a claim,
   * and the output beside it is the part that drifts silently when the layout changes. The
   * example-execution gate proves the code runs; this proves the comment is what it prints. */
  var exDer = b.sequence([b.integer(1), b.oid("2.5.4.3"), b.nullValue()]);
  check("A6: the docstring's example prints the report written beside it",
    pki.inspect.asn1(exDer) === [
      "ASN.1 structure: 12 bytes, decoded as DER",
      "    0:d=0  hl=2 l=  10 cons: SEQUENCE",
      "    2:d=1  hl=2 l=   1 prim:  INTEGER                  :1",
      "    5:d=1  hl=2 l=   3 prim:  OBJECT IDENTIFIER        :2.5.4.3 (commonName)",
      "   10:d=1  hl=2 l=   0 prim:  NULL",
      "Complete: the structure ends at offset 12, the end of the input.",
    ].join("\n"));
  check("A7: the docstring's truncated example prints the report written beside it",
    pki.inspect.asn1(exDer.subarray(0, 7)) === [
      "ASN.1 structure: 7 bytes, header walk",
      "DER decode refused: asn1/truncated: content length overruns the buffer",
      "    0:d=0  hl=2 l=  10 cons: SEQUENCE",
      "    2:d=1  hl=2 l=   1 prim:  INTEGER                  :1",
      "Incomplete: the walk could not read the value at offset 5: content length 3 overruns the " +
        "0 bytes that remain.",
    ].join("\n"));
  check("A8: the shared line formatter agrees with the literal control on every line",
    [line(0, 0, 2, 15, "cons", "SEQUENCE", null),
      line(2, 1, 2, 1, "prim", "INTEGER", "1"),
      line(5, 1, 2, 3, "prim", "OBJECT IDENTIFIER", "2.5.4.3 (commonName)"),
      line(10, 1, 2, 5, "cons", "SEQUENCE", null),
      line(12, 2, 2, 1, "prim", "BOOLEAN", "TRUE"),
      line(15, 2, 2, 0, "prim", "NULL", null)].join("\n") ===
      lines(CONTROL_REPORT).slice(1, 7).join("\n"));
}

function runOidNaming() {
  check("B1: a registered OID renders the dotted form and the registry name",
    lineWith(pki.inspect.asn1(b.oid("1.2.840.113549.1.1.11")), "OBJECT IDENTIFIER") ===
      line(0, 0, 2, 9, "prim", "OBJECT IDENTIFIER", "1.2.840.113549.1.1.11 (sha256WithRSAEncryption)"));
  check("B2: an unregistered OID renders the dotted form and no parenthetical",
    lineWith(pki.inspect.asn1(b.oid("1.3.6.1.4.1.99999.7.7")), "OBJECT IDENTIFIER") ===
      line(0, 0, 2, 10, "prim", "OBJECT IDENTIFIER", "1.3.6.1.4.1.99999.7.7"));
  check("B3: pki.oid.name has no entry for the OID B2 asserts is unnamed",
    pki.oid.name("1.3.6.1.4.1.99999.7.7") === undefined);
  var badOid = Buffer.from([0x06, 0x02, 0x80, 0x01]);
  check("B4: an OID whose content is not a valid encoding renders as hex rather than throwing",
    lineWith(pki.inspect.asn1(badOid), "OBJECT IDENTIFIER") ===
      line(0, 0, 2, 2, "prim", "OBJECT IDENTIFIER", "80:01"));
}

function runValueRendering() {
  function only(der, needle) { return lineWith(pki.inspect.asn1(der), needle); }

  check("C1: a small INTEGER renders its decimal magnitude",
    only(b.integer(65537), "INTEGER") === line(0, 0, 2, 3, "prim", "INTEGER", "65537"));
  check("C2: a negative INTEGER renders its signed magnitude",
    only(b.integer(-5), "INTEGER") === line(0, 0, 2, 1, "prim", "INTEGER", "-5"));
  check("C3: an INTEGER past a machine integer renders the exact magnitude and the content bytes",
    only(b.integer(123456789012345678901234567890n), "INTEGER") ===
      line(0, 0, 2, 13, "prim", "INTEGER",
        "123456789012345678901234567890 (0x018ee90ff6c373e0ee4e3f0ad2)"));
  check("C4: an ENUMERATED renders its magnitude",
    only(b.enumerated(3), "ENUMERATED") === line(0, 0, 2, 1, "prim", "ENUMERATED", "3"));
  check("C5: BOOLEAN 0x00 renders FALSE",
    only(b.boolean(false), "BOOLEAN") === line(0, 0, 2, 1, "prim", "BOOLEAN", "FALSE"));
  check("C6: a BOOLEAN that is neither 0x00 nor 0xff renders the byte, which is what DER forbids",
    lineWith(pki.inspect.asn1(Buffer.from([0x01, 0x01, 0x7f])), "BOOLEAN") ===
      line(0, 0, 2, 1, "prim", "BOOLEAN", "7f"));
  check("C7: an OCTET STRING renders a hex dump of its content",
    only(b.octetString(Buffer.from([0xde, 0xad, 0xbe, 0xef])), "OCTET STRING") ===
      line(0, 0, 2, 4, "prim", "OCTET STRING", "de:ad:be:ef"));
  check("C8: a BIT STRING renders the unused-bit count and the bytes",
    only(b.bitString(Buffer.from([0xf0]), 4), "BIT STRING") ===
      line(0, 0, 2, 2, "prim", "BIT STRING", "4 unused bits, f0"));
  check("C9: a printable string renders its text",
    only(b.printable("pkijs.com"), "PRINTABLE STRING") ===
      line(0, 0, 2, 9, "prim", "PRINTABLE STRING", "pkijs.com"));
  check("C10: a UTF8 string renders its text",
    only(b.utf8("blamejs pki"), "UTF8 STRING") ===
      line(0, 0, 2, 11, "prim", "UTF8 STRING", "blamejs pki"));
  check("C11: a string whose bytes are not printable renders as hex rather than as mojibake",
    lineWith(pki.inspect.asn1(Buffer.from([0x0c, 0x03, 0xe2, 0x9c, 0x93])), "UTF8 STRING") ===
      line(0, 0, 2, 3, "prim", "UTF8 STRING", "e2:9c:93"));
  check("C12: an empty value renders as empty rather than as a bare colon",
    only(b.octetString(Buffer.alloc(0)), "OCTET STRING") ===
      line(0, 0, 2, 0, "prim", "OCTET STRING", "(empty)"));
  var ctx = pki.inspect.asn1(b.sequence([b.contextPrimitive(0, Buffer.from([0x01, 0x02])),
    b.explicit(1, b.integer(5))]));
  check("C13: a primitive context tag renders [n] and a hex dump of its content",
    hasLine(ctx, line(2, 1, 2, 2, "prim", "[0]", "01:02")));
  check("C14: a constructed context tag renders [n] and walks its children",
    hasLine(ctx, line(6, 1, 2, 3, "cons", "[1]", null)) &&
      hasLine(ctx, line(8, 2, 2, 1, "prim", "INTEGER", "5")));
  check("C15: an application tag in the high-tag-number form renders its class, number and header length",
    lineWith(pki.inspect.asn1(Buffer.from([0x5f, 0x21, 0x01, 0x07])), "APPLICATION") ===
      line(0, 0, 3, 1, "prim", "APPLICATION [33]", "07"));
  check("C16: a universal tag the codec does not name renders its number and its bytes, " +
    "since its type is not knowable",
  lineWith(pki.inspect.asn1(Buffer.from([0x19, 0x02, 0x41, 0x42])), "UNIVERSAL") ===
      line(0, 0, 2, 2, "prim", "UNIVERSAL [25]", "41:42"));
  check("C17: an empty SEQUENCE renders as a constructed node with no children",
    pki.inspect.asn1(b.sequence([])).indexOf(line(0, 0, 2, 0, "cons", "SEQUENCE", null)) !== -1);
  check("C18: a SET renders as a SET",
    lineWith(pki.inspect.asn1(b.set([b.integer(1)])), "SET") ===
      line(0, 0, 2, 3, "cons", "SET", null));
}

function runTimeBytes() {
  /* Month 13: a Date rolls it into January of the next year, which is exactly the
   * malformation someone dumps a file to find. The strict DER decoder accepts the TLV
   * (the content is thirteen printable bytes), and pki.asn1.read.time is the layer that
   * refuses it, so this pair proves the dump reads neither through read.time nor a Date. */
  var badUtc = Buffer.concat([Buffer.from([0x17, 0x0d]), Buffer.from("261301030405Z", "latin1")]);
  check("D1: read.time refuses the fixture, so a dump that normalized it would be reading through a Date",
    codeOf(function () { pki.asn1.read.time(pki.asn1.decode(badUtc)); }) === "asn1/bad-time");
  check("D2: a UTCTime renders its on-the-wire bytes, month 13 included",
    lineWith(pki.inspect.asn1(badUtc), "UTC TIME") ===
      line(0, 0, 2, 13, "prim", "UTC TIME", "261301030405Z"));
  check("D3: a well-formed UTCTime also renders its bytes rather than a formatted date",
    lineWith(pki.inspect.asn1(b.utcTime(new Date("2026-01-02T03:04:05Z"))), "UTC TIME") ===
      line(0, 0, 2, 13, "prim", "UTC TIME", "260102030405Z"));
  check("D4: a GeneralizedTime renders its bytes",
    lineWith(pki.inspect.asn1(b.generalizedTime(new Date("2026-01-02T03:04:05Z"))), "GENERALIZED TIME") ===
      line(0, 0, 2, 15, "prim", "GENERALIZED TIME", "20260102030405Z"));
  var fractional = Buffer.concat([Buffer.from([0x18, 0x13]),
    Buffer.from("20260102030405.500Z", "latin1")]);
  check("D5: a GeneralizedTime with a fractional second renders it, which DER forbids and a Date drops",
    lineWith(pki.inspect.asn1(fractional), "GENERALIZED TIME") ===
      line(0, 0, 2, 19, "prim", "GENERALIZED TIME", "20260102030405.500Z"));
}

function runRoutes() {
  check("E1: a conforming input names the DER route",
    lines(pki.inspect.asn1(CONTROL))[0] === "ASN.1 structure: 17 bytes, decoded as DER");

  /* An indefinite length is not DER, so it reaches the walk. The walk renders what is on
   * the wire: the length column says inf and the end-of-contents octets are a node. A BER
   * decode would resolve the length to 3 and hide the encoding the dump exists to show. */
  var indef = Buffer.from([0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]);
  check("E2: the DER decoder refuses the indefinite-length fixture",
    codeOf(function () { pki.asn1.decode(indef); }) === "asn1/indefinite-length");
  var indefReport = pki.inspect.asn1(indef);
  check("E3: an indefinite length names the walk and the reason DER refused it",
    lines(indefReport)[0] === "ASN.1 structure: 7 bytes, header walk" &&
      lines(indefReport)[1] ===
        "DER decode refused: asn1/indefinite-length: indefinite length is not valid DER");
  check("E4: an indefinite length renders as inf rather than as a resolved content length",
    hasLine(indefReport, line(0, 0, 2, "inf", "cons", "SEQUENCE", null)) &&
      hasLine(indefReport, line(2, 1, 2, 1, "prim", "INTEGER", "1")));
  check("E5: the end-of-contents octets are rendered as a node of their own",
    hasLine(indefReport, line(5, 1, 2, 0, "prim", "EOC", null)));
  check("E6: the indefinite structure's end offset counts the end-of-contents octets",
    hasLine(indefReport, "Complete: the structure ends at offset 7, the end of the input."));

  /* A segmented OCTET STRING is the other shape a BER decode would rewrite: it reassembles
   * the segments, so the value it reports is not the one on the wire. The walk shows the
   * segments as the nested values they are. */
  var segmented = Buffer.from([0x24, 0x08, 0x04, 0x02, 0xaa, 0xbb, 0x04, 0x02, 0xcc, 0xdd]);
  var segReport = pki.inspect.asn1(segmented);
  check("E7: a segmented OCTET STRING reaches the walk",
    lines(segReport)[0] === "ASN.1 structure: 10 bytes, header walk" &&
      lines(segReport)[1].indexOf("asn1/constructed-primitive-type") !== -1);
  check("E8: the segments render as the values they are, with the outer length as written",
    hasLine(segReport, line(0, 0, 2, 8, "cons", "OCTET STRING", null)) &&
      hasLine(segReport, line(2, 1, 2, 2, "prim", "OCTET STRING", "aa:bb")) &&
      hasLine(segReport, line(6, 1, 2, 2, "prim", "OCTET STRING", "cc:dd")));

  var nonMinimal = Buffer.from([0x02, 0x81, 0x01, 0x07]);
  check("E9: the strict decoder refuses the non-minimal-length fixture",
    codeOf(function () { pki.asn1.decode(nonMinimal); }) === "asn1/non-minimal-length");
  var nmReport = pki.inspect.asn1(nonMinimal);
  check("E10: a non-minimal length names the header walk and why the strict decoder refused",
    lines(nmReport)[0] === "ASN.1 structure: 4 bytes, header walk" &&
      lines(nmReport)[1] === "DER decode refused: asn1/non-minimal-length: " +
        "long form used for a length < 128");
  check("E11: the walk reads the non-minimal length and renders the value it carries",
    hasLine(nmReport, line(0, 0, 3, 1, "prim", "INTEGER", "7")) &&
      hasLine(nmReport, "Complete: the structure ends at offset 4, the end of the input."));

  var primitiveSequence = Buffer.from([0x10, 0x03, 0x02, 0x01, 0x01]);
  /* X.690 sec. 8.1.5 gives the end-of-contents value a zero length, so a tag-0 value carrying
   * content is not one and is not a terminator. `openssl asn1parse` pops a level on the
   * identifier alone and ends that file with a dangling end-of-contents value; holding to the
   * clause keeps the opened and closed values balanced. */
  var falseEoc = Buffer.from([0x30, 0x80, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x00]);
  var falseEocReport = pki.inspect.asn1(falseEoc);
  check("E12: a tag-0 value carrying content is not named an end-of-contents value",
    hasLine(falseEocReport, line(2, 1, 2, 2, "prim", "UNIVERSAL [0]", "aa:bb")));
  check("E13: the real end-of-contents value after it is named and closes the structure",
    hasLine(falseEocReport, line(6, 1, 2, 0, "prim", "EOC", null)) &&
      hasLine(falseEocReport, "Complete: the structure ends at offset 8, the end of the input."));

  check("E14: a SEQUENCE encoded primitive renders as primitive rather than being walked as one",
    hasLine(pki.inspect.asn1(primitiveSequence), line(0, 0, 2, 3, "prim", "SEQUENCE", "02:01:01")));
}

function runIncomplete() {
  var truncated = CONTROL.subarray(0, 8);
  check("F1: the strict decoder refuses the truncated fixture",
    codeOf(function () { pki.asn1.decode(truncated); }) === "asn1/truncated");
  var tReport = pki.inspect.asn1(truncated);
  check("F2: a truncated structure still reports the prefix it could read",
    hasLine(tReport, line(0, 0, 2, 15, "cons", "SEQUENCE", null)) &&
      hasLine(tReport, line(2, 1, 2, 1, "prim", "INTEGER", "1")));
  check("F3: a truncated structure names the offset where the walk stopped and says it did not complete",
    hasLine(tReport, "Incomplete: the walk could not read the value at offset 5: " +
      "content length 3 overruns the 1 byte that remains."));
  check("F4: no node past the stop offset is rendered, and the two before it are",
    lineWith(tReport, "OBJECT IDENTIFIER") === null && lines(tReport).length === 5);

  var trailing = Buffer.concat([CONTROL, Buffer.from([0xaa, 0xbb])]);
  check("F5: the strict decoder refuses trailing bytes",
    codeOf(function () { pki.asn1.decode(trailing); }) === "asn1/trailing-bytes");
  var trReport = pki.inspect.asn1(trailing);
  check("F6: trailing bytes are reported as trailing rather than dropped",
    hasLine(trReport, "Incomplete: 2 bytes at offset 17 follow the top-level value."));
  check("F7: the top-level value before the trailing bytes is rendered in full",
    hasLine(trReport, line(0, 0, 2, 15, "cons", "SEQUENCE", null)) &&
      hasLine(trReport, line(15, 2, 2, 0, "prim", "NULL", null)));

  var headerCut = Buffer.from([0x30, 0x82, 0x01]);
  var hcReport = pki.inspect.asn1(headerCut);
  check("F8: a header cut mid-length names the offset and renders no node",
    hasLine(hcReport, "Incomplete: the walk could not read the value at offset 0: " +
      "the long-form length runs past the end of the input.") &&
      lineWith(hcReport, ":d=0") === null);

  var indefPrimitive = Buffer.from([0x02, 0x80, 0x01, 0x00, 0x00]);
  check("F9: an indefinite length on a primitive is refused by a BER decode too",
    codeOf(function () { pki.asn1.decode(indefPrimitive, { ber: true }); }) === "asn1/indefinite-length");
  check("F10: the walk names an indefinite length rather than reading 0x80 as a zero length",
    hasLine(pki.inspect.asn1(indefPrimitive), "Incomplete: the walk could not read the value at " +
      "offset 0: an indefinite length on a primitive value has no end-of-contents octets to find."));

  var childOverrun = Buffer.from([0x30, 0x04, 0x02, 0x05, 0x01, 0x02]);
  check("F11: a child whose length overruns its parent is named against the parent's end",
    hasLine(pki.inspect.asn1(childOverrun), "Incomplete: the walk could not read the value at " +
      "offset 2: content length 5 overruns the 2 bytes that remain."));
}

function runCaps() {
  var C = pki.C.LIMITS;
  check("G1: the dump's caps are published limits rather than literals in the renderer",
    typeof C.DUMP_MAX_NODES === "number" && C.DUMP_MAX_NODES > 0 &&
      typeof C.DUMP_MAX_VALUE_BYTES === "number" && C.DUMP_MAX_VALUE_BYTES > 0);

  function nest(n) { var x = b.integer(1); for (var i = 0; i < n; i++) x = b.sequence([x]); return x; }
  var deep = nest(C.DER_MAX_DEPTH + 6);
  check("G2: the strict decoder refuses nesting past the depth cap",
    codeOf(function () { pki.asn1.decode(deep); }) === "asn1/too-deep");
  var deepReport = pki.inspect.asn1(deep);
  check("G3: the walk stops at the depth cap and names it",
    lineWith(deepReport, "Incomplete: the walk could not read the value at offset ") !== null &&
      lineWith(deepReport, "nesting exceeds the depth cap " + C.DER_MAX_DEPTH + ".") !== null);
  check("G4: the deepest rendered node is at the cap and nothing past it is rendered",
    lineWith(deepReport, ":d=" + C.DER_MAX_DEPTH + " ") !== null &&
      lineWith(deepReport, ":d=" + (C.DER_MAX_DEPTH + 1) + " ") === null);

  /* One large input rather than a ratio: a structure of exactly cap + 1 nodes, counting the
   * enclosing SEQUENCE. That is the largest tree the strict decoder is given, so the report
   * stops at the cap on the strict route and its line count is bounded by the cap. */
  var kids = [];
  for (var i = 0; i < C.DUMP_MAX_NODES; i++) kids.push(b.nullValue());
  var wide = b.sequence(kids);
  check("G5: the strict decoder accepts the wide fixture, so the node cap is proven on the DER route",
    codeOf(function () { pki.asn1.decode(wide); }) === "NO-THROW");
  var wideReport = pki.inspect.asn1(wide);
  check("G6: a structure past the node cap stops at the cap and says so",
    lines(wideReport)[0].indexOf("decoded as DER") !== -1 &&
      hasLine(wideReport, "Incomplete: the report stopped after " + C.DUMP_MAX_NODES +
        " nodes, the cap on one dump; the next value begins at offset " +
        (wide.length - 2) + "."));
  check("G7: the report's line count is the node cap and not the input's node count",
    lines(wideReport).length >= C.DUMP_MAX_NODES &&
      lines(wideReport).length <= C.DUMP_MAX_NODES + 4);

  var long = b.octetString(Buffer.alloc(C.DUMP_MAX_VALUE_BYTES + 32, 0x5a));
  var longReport = pki.inspect.asn1(long);
  check("G8: a value past the value cap renders the cap's worth and counts the rest",
    lineWith(longReport, "(32 more bytes not rendered)") !== null &&
      longReport.indexOf("5a:5a:5a:5a") !== -1);

  check("G9: maxNodes is settable and the report names the cap it was given",
    hasLine(pki.inspect.asn1(CONTROL, { maxNodes: 2 }),
      "Incomplete: the report stopped after 2 nodes, the cap on one dump; " +
      "the next value begins at offset 5."));
  check("G10: a depth cap given by the caller is honored",
    hasLine(pki.inspect.asn1(CONTROL, { maxDepth: 1 }),
      "Incomplete: the walk could not read the value at offset 12: nesting exceeds the depth cap 1."));
  check("G11: a value cap given by the caller is honored",
    lineWith(pki.inspect.asn1(b.octetString(Buffer.alloc(8, 0x11)), { maxValueBytes: 2 }),
      "(6 more bytes not rendered)") !== null);
  check("G12: a byte cap given by the caller refuses an input past it",
    codeOf(function () { pki.inspect.asn1(CONTROL, { maxBytes: 4 }); }) === "inspect/bad-input");
  /* A byte-at-a-time magnitude over attacker-length content is quadratic, so the dump reads a
   * magnitude only inside the per-value cap asn1.read.integer applies and renders the bytes past
   * it. One large input rather than a ratio: one INTEGER a byte over the cap. */
  var over = C.DER_MAX_INTEGER_BYTES + 2;
  var huge = Buffer.concat([Buffer.from([0x02, 0x82, (over >> 8) & 0xff, over & 0xff]),
    Buffer.alloc(over, 0x01)]);
  var hugeReport = pki.inspect.asn1(huge);
  check("G13: an INTEGER past the per-value byte cap renders its bytes, not a magnitude",
    lines(hugeReport)[0].indexOf("decoded as DER") !== -1 &&
      lineWith(hugeReport, "INTEGER") === line(0, 0, 4, over, "prim", "INTEGER",
        new Array(C.DUMP_MAX_VALUE_BYTES).fill("01").join(":") +
        " (" + (over - C.DUMP_MAX_VALUE_BYTES) + " more bytes not rendered)"));
  check("G14: with the value cap raised past the content, the codec's own integer cap still refuses " +
    "to read a magnitude, and read.integer refuses the same content",
  lineWith(pki.inspect.asn1(huge, { maxValueBytes: over + 1 }), "INTEGER") ===
      line(0, 0, 4, over, "prim", "INTEGER", new Array(over).fill("01").join(":")) &&
    codeOf(function () { pki.asn1.read.integer(pki.asn1.decode(huge)); }) === "asn1/integer-too-large");
  check("G15: a value cap below the content length yields the bytes rather than a magnitude, " +
    "since a magnitude read from more content than the cap allows is a read past the cap",
  lineWith(pki.inspect.asn1(b.integer(123456789012345678901234567890n), { maxValueBytes: 4 }),
    "INTEGER") === line(0, 0, 2, 13, "prim", "INTEGER",
    "01:8e:e9:0f (9 more bytes not rendered)"));

  /* The value cap bounds how many bytes of one value the report READS, so every rendering
   * derived from content has to consult it: a text rendering and a decoded form as much as a
   * hex dump. A branch that renders its whole content is the class this table closes. */
  var CAPPED = [
    ["BOOLEAN", 1], ["INTEGER", 2], ["BIT STRING", 3], ["OCTET STRING", 4], ["NULL", 5],
    ["OBJECT IDENTIFIER", 6], ["UTF8 STRING", 12], ["NUMERIC STRING", 18],
    ["PRINTABLE STRING", 19], ["TELETEX STRING", 20], ["IA5 STRING", 22], ["UTC TIME", 23],
    ["GENERALIZED TIME", 24], ["VISIBLE STRING", 26], ["UNIVERSAL STRING", 28],
    ["BMP STRING", 30], ["UNIVERSAL [25]", 25], ["[7]", 0x87], ["APPLICATION [3]", 0x43],
  ];
  /* The bound is derived from the layout rather than picked: the fixed head, the name column,
   * three characters per rendered byte, and the longest omission note plus the bit-string
   * prefix. Every tag type measured at a 4-byte cap lands between 90 and 113 characters. */
  var CAP4 = 4;
  var BOUND = 40 + NAME_COLUMN + 3 * CAP4 + 48;
  var unbounded = [];
  CAPPED.forEach(function (row) {
    var der = Buffer.concat([Buffer.from([row[1], 0x82, 0x01, 0x90]), Buffer.alloc(400, 0x37)]);
    var rendered;
    try { rendered = lineWith(pki.inspect.asn1(der, { maxValueBytes: CAP4 }), row[0]); }
    catch (e) { unbounded.push(row[0] + " threw " + (e.code || e.constructor.name)); return; }
    if (rendered === null) { unbounded.push(row[0] + " rendered no line"); return; }
    if (rendered.length > BOUND) {
      unbounded.push(row[0] + " line is " + rendered.length + " chars, over " + BOUND);
    }
    if (rendered.indexOf("more bytes not rendered") === -1) {
      unbounded.push(row[0] + " states no omission: " + rendered.slice(-40));
    }
  });
  check("G16: every value rendering honors the value cap and states what it omitted (" +
    CAPPED.length + " tag types): " + unbounded.join("; "), unbounded.length === 0);
  check("G17: a printable string past the cap renders the cap's worth and counts the rest",
    lineWith(pki.inspect.asn1(b.utf8("abcdefghij"), { maxValueBytes: 4 }), "UTF8 STRING") ===
      line(0, 0, 2, 10, "prim", "UTF8 STRING", "abcd (6 more bytes not rendered)"));
  check("G18: a time past the cap renders the cap's worth and counts the rest",
    lineWith(pki.inspect.asn1(b.utcTime(new Date("2026-01-02T03:04:05Z")), { maxValueBytes: 6 }),
      "UTC TIME") === line(0, 0, 2, 13, "prim", "UTC TIME", "260102 (7 more bytes not rendered)"));
  check("G19: an OID whose content is past the cap renders the bytes rather than decoding it",
    lineWith(pki.inspect.asn1(b.oid("1.2.840.113549.1.1.11"), { maxValueBytes: 4 }),
      "OBJECT IDENTIFIER") === line(0, 0, 2, 9, "prim", "OBJECT IDENTIFIER",
      "2a:86:48:86 (5 more bytes not rendered)"));

  /* The strict decoder builds the whole node tree before the renderer counts a line, so the
   * report's node cap has to reach the decoder as its item cap or a file of small values
   * allocates a tree the report will never print. The coupling is observable: a cap below the
   * input's node count sends the report to the walk, naming the decoder's own refusal. */
  check("G20: a node cap below the input's node count is enforced by the decoder, not only the report",
    lines(pki.inspect.asn1(CONTROL, { maxNodes: 1 }))[1] ===
      "DER decode refused: asn1/too-many-items: decoded DER node count exceeds the cap 2");
  check("G21: a structure one node past the cap still takes the strict route, so the decoder is " +
    "given one node more than the report prints",
  lines(pki.inspect.asn1(wide))[0].indexOf("decoded as DER") !== -1);

  /* A report that stopped at the node cap has to name WHERE, or the reader cannot tell which
   * part of the file the report covers and has no offset to resume a second dump from. */
  check("G23: a report stopped by the node cap names the offset the next value begins at",
    hasLine(pki.inspect.asn1(Buffer.from([0x30, 0x80, 0x05, 0x00, 0x00, 0x00]), { maxNodes: 1 }),
      "Incomplete: the report stopped after 1 node, the cap on one dump; " +
      "the next value begins at offset 2."));
  check("G24: the same stop on the strict route also names the offset",
    hasLine(pki.inspect.asn1(CONTROL, { maxNodes: 3 }),
      "Incomplete: the report stopped after 3 nodes, the cap on one dump; " +
      "the next value begins at offset 10."));

  /* The offset a stop names is the value the walk could not read through, not the position
   * reading had advanced to. An unterminated indefinite length is the case that separates the
   * two: the walk reads every byte available and the value at offset 0 is still the one at fault. */
  check("G25: an unterminated indefinite length faults the value that is unterminated",
    hasLine(pki.inspect.asn1(Buffer.from([0x30, 0x80, 0x05, 0x00])),
      "Incomplete: the walk could not read the value at offset 0: the indefinite-length value " +
      "has no end-of-contents octets before the end of the input."));

  /* The end-of-contents octets are a node the walk emits without recursing, so the depth cap has
   * to be applied to them where they are pushed. An indefinite-length value with no children is
   * the only input that reaches the EOC without a child having been walked first. */
  var emptyIndef = Buffer.from([0x30, 0x80, 0x00, 0x00]);
  check("G26: the end-of-contents node is held to the depth cap like any other node",
    hasLine(pki.inspect.asn1(emptyIndef, { maxDepth: 0 }),
      "Incomplete: the walk could not read the value at offset 2: nesting exceeds the depth cap 0.") &&
      lineWith(pki.inspect.asn1(emptyIndef, { maxDepth: 0 }), ":d=1 ") === null);
  check("G27: the same value renders its end-of-contents node when the depth cap allows it",
    hasLine(pki.inspect.asn1(emptyIndef), line(2, 1, 2, 0, "prim", "EOC", null)) &&
      hasLine(pki.inspect.asn1(emptyIndef),
        "Complete: the structure ends at offset 4, the end of the input."));

  /* A rendering whose size grows with the content consults the value cap; a fixed-size decoded
   * form does not, and these two vectors are what pins which is which. */
  check("G28: a BOOLEAN renders its verdict at any value cap, since the verdict is one word",
    lineWith(pki.inspect.asn1(b.boolean(true), { maxValueBytes: 0 }), "BOOLEAN") ===
      line(0, 0, 2, 1, "prim", "BOOLEAN", "TRUE"));
  check("G29: a BIT STRING renders its unused-bit count at any value cap and caps only the body",
    lineWith(pki.inspect.asn1(b.bitString(Buffer.from([0xaa, 0xbb]), 0), { maxValueBytes: 1 }),
      "BIT STRING") === line(0, 0, 2, 3, "prim", "BIT STRING",
      "0 unused bits, aa (1 more byte not rendered)"));

  /* A tag name the name column cannot hold still gets one space before the colon, so the value
   * never runs into the type name. Nine levels of nesting under a 17-character type name is the
   * shortest input that reaches it, and a real certificate's extensions get close. */
  var deepOid = b.oid("2.5.4.3");
  for (var w = 0; w < 9; w++) deepOid = b.sequence([deepOid]);
  check("G30: a name the column cannot hold keeps one space before the value",
    lineWith(pki.inspect.asn1(deepOid), "OBJECT IDENTIFIER") ===
      line(18, 9, 2, 3, "prim", "OBJECT IDENTIFIER", "2.5.4.3 (commonName)"));

  check("G31: a value cap of zero renders the omission on its own, with no empty prefix",
    lineWith(pki.inspect.asn1(b.octetString(Buffer.from([0xaa])), { maxValueBytes: 0 }),
      "OCTET STRING") === line(0, 0, 2, 1, "prim", "OCTET STRING", "(1 more byte not rendered)"));

  check("G32: an INTEGER with no content octets renders as empty rather than as a magnitude",
    lineWith(pki.inspect.asn1(Buffer.from([0x02, 0x00])), "INTEGER") ===
      line(0, 0, 2, 0, "prim", "INTEGER", "(empty)"));

  var wideTag = Buffer.from([0x5f, 0xff, 0xff, 0xff, 0xff, 0x01, 0x07]);
  check("G33: a tag number past four octets stops the walk and names the cap",
    hasLine(pki.inspect.asn1(wideTag), "Incomplete: the walk could not read the value at offset 0: " +
      "the tag number uses more than 4 octets."));

  check("G34: the node cap applies to the end-of-contents node as well as to a value",
    hasLine(pki.inspect.asn1(Buffer.from([0x30, 0x80, 0x05, 0x00, 0x00, 0x00]), { maxNodes: 2 }),
      "Incomplete: the report stopped after 2 nodes, the cap on one dump; " +
      "the next value begins at offset 4."));

  check("G35: a cap that is not a non-negative integer is refused at the door",
    codeOf(function () { pki.inspect.asn1(CONTROL, { maxDepth: -1 }); }) === "TypeError" &&
      codeOf(function () { pki.inspect.asn1(CONTROL, { maxNodes: 1.5 }); }) === "TypeError" &&
      codeOf(function () { pki.inspect.asn1(CONTROL, { maxValueBytes: "8" }); }) === "TypeError");
}

function runDoors() {
  check("H1: a non-DER, non-PEM input is refused with inspect/bad-input",
    codeOf(function () { pki.inspect.asn1(42); }) === "inspect/bad-input" &&
      codeOf(function () { pki.inspect.asn1(null); }) === "inspect/bad-input" &&
      codeOf(function () { pki.inspect.asn1({ tagNumber: 16 }); }) === "inspect/bad-input");
  check("H2: an empty input is refused rather than reported as an empty structure",
    codeOf(function () { pki.inspect.asn1(Buffer.alloc(0)); }) === "inspect/bad-input");
  check("H3: an unknown option is refused rather than ignored",
    codeOf(function () { pki.inspect.asn1(CONTROL, { maxdepth: 4 }); }) === "inspect/bad-input");
  check("H4: the verb returns a string and never a parsed tree",
    typeof pki.inspect.asn1(CONTROL) === "string");
  check("H5: an options argument that is not an object is refused",
    codeOf(function () { pki.inspect.asn1(CONTROL, 7); }) === "inspect/bad-input");
}

async function runConsumerPath() {
  var certDer = pki.schema.x509.pemDecode(helpers.vectors.CERT_EC_PEM, "CERTIFICATE");
  var report = pki.inspect.asn1(certDer);
  var root = pki.asn1.decode(certDer);
  check("I1: a real certificate's root line carries the certificate's own measured header and length",
    hasLine(report, line(0, 0, root.header.end - root.header.start, root.length, "cons", "SEQUENCE", null)));
  check("I2: the certificate's signature algorithm OID is named in the dump",
    lineWith(report, "(ecdsaWithSHA256)") !== null);
  check("I3: the certificate's serial renders its magnitude and its content bytes",
    lineWith(report, "(0x" + helpers.vectors.CERT_EC_EXPECT.serialHex + ")") !== null);
  check("I4: the certificate's notBefore renders its on-the-wire bytes",
    lineWith(report, "260704070027Z") !== null);
  check("I5: a real certificate reports as complete",
    hasLine(report, "Complete: the structure ends at offset " + certDer.length +
      ", the end of the input."));
  check("I6: the certificate's first four lines are the ones the structure measures",
    lines(report).slice(1, 5).join("\n") === [
      "    0:d=0  hl=4 l= 544 cons: SEQUENCE",
      "    4:d=1  hl=4 l= 453 cons:  SEQUENCE",
      "    8:d=2  hl=2 l=   3 cons:   [0]",
      "   10:d=3  hl=2 l=   1 prim:    INTEGER                :2",
    ].join("\n"));
  check("I7: every extension OID in the certificate is named in the dump",
    helpers.vectors.CERT_EC_EXPECT.extnOids.every(function (o) {
      return lineWith(report, ":" + o + " (") !== null;
    }));

  /* The dump is a byte-level tool and renders every value in the input, a private key
   * included. pki.inspect.any keeps the guarantee that a report on a key-bearing file
   * prints no byte string from it, which holds only while `any` never routes to the dump. */
  var pair = await pki.key.generate("ML-DSA-65");
  var pkcs8 = await pki.key.export(pair.privateKey);
  var dump = pki.inspect.asn1(pkcs8);
  check("I8: a PKCS#8 dumps through the DER route",
    lines(dump)[0].indexOf("decoded as DER") !== -1);
  var keyBytes = pki.asn1.decode(pkcs8).children[2].content;
  var keyHexColon = keyBytes.toString("hex").split("").reduce(function (acc, ch, idx) {
    return acc + (idx > 0 && idx % 2 === 0 ? ":" : "") + ch;
  }, "");
  check("I9: the dump renders the private key bytes, which is what a byte-level tool does",
    keyBytes.length > 8 && dump.indexOf(keyHexColon) !== -1);
  var structured = pki.inspect.any(pkcs8);
  check("I10: pki.inspect.any on the same file renders no byte string from it and is not the dump",
    structured !== dump && structured.indexOf("Private Key: present") !== -1 &&
      structured.indexOf(keyBytes.toString("hex")) === -1);
}

function runHostileBytes() {
  /* The walk reads attacker-controlled bytes, so every result must be a report or the
   * documented typed error. An untyped TypeError out of a renderer is the failure this
   * probe exists to find. */
  var certDer = pki.schema.x509.pemDecode(helpers.vectors.CERT_EC_PEM, "CERTIFICATE");
  var faults = [];
  var values = [0x00, 0x01, 0x30, 0x80, 0x81, 0xa0, 0xff];
  var step = 3;
  var mutations = 0;
  for (var i = 0; i < certDer.length; i += step) {
    for (var v = 0; v < values.length; v++) {
      var mutated = Buffer.from(certDer);
      mutated[i] = values[v];
      mutations += 1;
      try {
        if (typeof pki.inspect.asn1(mutated) !== "string") faults.push("offset " + i + " -> non-string");
      } catch (e) {
        if (e.code !== "inspect/bad-input") {
          faults.push("offset " + i + " byte " + values[v] + " -> " + (e.code || e.constructor.name));
        }
      }
    }
  }
  check("J1: every single-byte corruption of a real certificate yields a report or inspect/bad-input (" +
    mutations + " mutations): " + faults.slice(0, 4).join("; "), faults.length === 0);

  var truncFaults = [];
  for (var n = 1; n < certDer.length; n += 7) {
    try {
      if (typeof pki.inspect.asn1(certDer.subarray(0, n)) !== "string") truncFaults.push("len " + n);
    } catch (e) {
      if (e.code !== "inspect/bad-input") truncFaults.push("len " + n + " -> " + (e.code || e.constructor.name));
    }
  }
  check("J2: every truncation of a real certificate yields a report or inspect/bad-input: " +
    truncFaults.slice(0, 4).join("; "), truncFaults.length === 0);

  var randomFaults = [];
  var seed = 0x2545f491;
  for (var r = 0; r < 600; r++) {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    var len = 1 + (seed % 40);
    var buf = Buffer.alloc(len);
    for (var k = 0; k < len; k++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      buf[k] = (seed >> 7) & 0xff;
    }
    try {
      if (typeof pki.inspect.asn1(buf) !== "string") randomFaults.push(buf.toString("hex"));
    } catch (e) {
      if (e.code !== "inspect/bad-input") randomFaults.push(buf.toString("hex") + " -> " + (e.code || e.constructor.name));
    }
  }
  check("J3: 600 pseudorandom byte strings each yield a report or inspect/bad-input: " +
    randomFaults.slice(0, 3).join("; "), randomFaults.length === 0);
}

/** The four numeric columns and the form, read off one dump line. Both this report and
 *  `openssl asn1parse` write them in the same fixed layout, so the tuples are directly
 *  comparable and the comparison is exact rather than value-level. */
function columnsOf(report) {
  return lines(report).map(function (ln) {
    var m = /^\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+)\s+(cons|prim):/.exec(ln);
    return m === null ? null : m[1] + ":" + m[2] + ":" + m[3] + ":" + m[4] + ":" + m[5];
  }).filter(function (x) { return x !== null; });
}

function findOpenssl() {
  var candidates = ["C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe", "openssl",
    "/usr/bin/openssl", "/usr/local/bin/openssl"];
  for (var i = 0; i < candidates.length; i++) {
    try { cp.execFileSync(candidates[i], ["version"], { stdio: "ignore" }); return candidates[i]; }
    catch (_e) { /* try the next candidate */ }
  }
  return null;
}

/* `openssl asn1parse` is the tool this dump is shaped after, and it writes the offset, the
 * depth, the header length, the content length and the form in the same fixed columns. That
 * makes it an independent oracle for the numbers, which are the load-bearing part of the
 * report: a vector comparing the dump against itself could agree with a wrong walk, and this
 * one cannot. The tag names and the rendered values are deliberately not compared, since this
 * report names OIDs from the toolkit's own registry and renders a time as written. */
function runOpensslInterop() {
  var ossl = findOpenssl();
  if (ossl === null) {
    helpers.skip("interop: openssl asn1parse column comparison (no openssl binary on PATH)");
    return;
  }
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pki-asn1-dump-"));
  var certDer = pki.schema.x509.pemDecode(helpers.vectors.CERT_EC_PEM, "CERTIFICATE");
  var subjects = [["the hand-computed control", CONTROL], ["a real certificate", certDer]];
  var disagreements = [];
  subjects.forEach(function (s) {
    var file = path.join(dir, "subject.der");
    fs.writeFileSync(file, s[1]);
    var out = cp.execFileSync(ossl, ["asn1parse", "-inform", "DER", "-in", file],
      { encoding: "latin1" });
    var theirs = columnsOf(out);
    var ours = columnsOf(pki.inspect.asn1(s[1]));
    if (theirs.length === 0) { disagreements.push(s[0] + ": openssl produced no lines"); return; }
    if (theirs.join("|") !== ours.join("|")) {
      disagreements.push(s[0] + ": " + theirs.length + " openssl lines vs " + ours.length +
        " ours; first difference " + JSON.stringify(theirs.filter(function (t, i) {
          return ours[i] !== t;
        })[0]) + " vs " + JSON.stringify(ours.filter(function (o, i) {
        return theirs[i] !== o;
      })[0]));
    }
  });
  fs.rmSync(dir, { recursive: true, force: true });
  check("interop: every offset, depth, header length, content length and form agrees with " +
    "openssl asn1parse: " + disagreements.join("; "), disagreements.length === 0);
}

async function run() {
  runControl();
  runOidNaming();
  runValueRendering();
  runTimeBytes();
  runRoutes();
  runIncomplete();
  runCaps();
  runDoors();
  await runConsumerPath();
  runHostileBytes();
  runOpensslInterop();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
