// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- pki.x509.parseDn (RFC 4514 distinguished-name string parsing).
 *
 * Every parsed name already carries `.dn`, its RFC 4514 string form. Reading one back was
 * missing, so a caller holding a DN string could not build a certificate from it without
 * assembling the RDN structure by hand.
 *
 * Oracle: the worked examples of RFC 4514 sec. 4, which state the string and the components
 * it denotes. The toolkit's own emitter is never the oracle for what a string means, so an
 * emitter bug cannot make a vector pass.
 *
 * One deliberate divergence, pinned below so it cannot drift: components are read in the
 * order they are written. RFC 4514 sec. 2.1 specifies the opposite order, and this toolkit
 * emits every `dn` first-component-first, the order `openssl x509 -subject` prints. The verb
 * is the inverse of that emitter, so it reads the same way.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;
var b = pki.asn1.build;

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || e.name; } }
function flatValues(r) {
  return r.rdns.map(function (rdn) {
    return rdn.map(function (a) { return (a.name || a.type) + "=" + a.value; }).join("+");
  });
}

// RFC 4514 sec. 4. Each entry is the RFC's string and the components the RFC says it names,
// listed in the order they are written.
function testRfcExamples() {
  var examples = [
    ["UID=jsmith,DC=example,DC=net",
      ["userId=jsmith", "domainComponent=example", "domainComponent=net"]],
    ["OU=Sales+CN=J.  Smith,DC=example,DC=net",
      ["organizationalUnitName=Sales+commonName=J.  Smith", "domainComponent=example", "domainComponent=net"]],
    ["CN=James \\\"Jim\\\" Smith\\, III,DC=example,DC=net",
      ["commonName=James \"Jim\" Smith, III", "domainComponent=example", "domainComponent=net"]],
    ["CN=Lu\\C4\\8Di\\C4\\87",
      ["commonName=Lučić"]],
  ];
  examples.forEach(function (row, i) {
    var parsed = pki.x509.parseDn(row[0]);
    check("RFC 4514 sec. 4 example " + (i + 1) + " parses to the components the RFC names",
      flatValues(parsed).join(" | ") === row[1].join(" | "));
  });

  // The carriage-return example. The RFC writes the value as Before\0dAfter; asserting the
  // code point rather than the rendered string keeps this file pure ASCII.
  var cr = pki.x509.parseDn("CN=Before\\0dAfter,DC=example,DC=net");
  var crValue = cr.rdns[0][0].value;
  check("RFC 4514 sec. 4 carriage-return example decodes \\0d to U+000D",
    crValue.length === 12 && crValue.charCodeAt(6) === 0x0d &&
    crValue.slice(0, 6) === "Before" && crValue.slice(7) === "After");

  // The five-letter example states each code point in a table, which is the strongest form
  // of this check: a parser decoding each \XX as its own character gets seven, not five.
  var lu = pki.x509.parseDn("CN=Lu\\C4\\8Di\\C4\\87").rdns[0][0].value;
  check("RFC 4514 sec. 4 five-letter example is five code points, not seven escapes",
    lu.length === 5);
  check("and each code point is the one the RFC's table gives",
    lu.charCodeAt(0) === 0x4c && lu.charCodeAt(1) === 0x75 && lu.charCodeAt(2) === 0x10d &&
    lu.charCodeAt(3) === 0x69 && lu.charCodeAt(4) === 0x107);
}

// The ordering this verb implements, pinned so it cannot drift silently in either direction:
// written order is encoded order, which is what the emitter produces and the inverse of it
// must therefore consume. RFC 4514 sec. 2.1 specifies the opposite, and a string from a
// directory tool following it must be reversed before it is parsed here.
function testComponentOrder() {
  var parsed = pki.x509.parseDn("C=US, O=Example Inc, CN=leaf");
  check("the string's first component is the encoded name's FIRST RDN",
    parsed.rdns[0][0].name === "countryName");
  check("the string's last component is the encoded name's LAST RDN",
    parsed.rdns[parsed.rdns.length - 1][0].name === "commonName");
  check("re-emitting writes the components in the order they were given",
    parsed.dn === "C=US, O=Example Inc, CN=leaf");
  // The encoded Name really does carry them in that order, read back through the DER rather
  // than through this verb's own result.
  var nameSeq = pki.asn1.decode(parsed.bytes);
  check("and the encoded SEQUENCE holds the same order",
    pki.asn1.read.oid(nameSeq.children[0].children[0].children[0]) === pki.oid.byName("countryName"));
}

// The round trip that matters to a caller: a string in, encoded Name out, and the Name reads
// back to the same string.
function testRoundTrip() {
  var strings = [
    "CN=example.com",
    "CN=leaf, O=Example Inc, C=US",
    "OU=Ops+CN=shared",
    "CN=a\\,b",
    "CN=a\\+b",
    "CN=a\\\"b",
    "CN=a\\\\b",
    "CN=a\\<b",
    "CN=a\\>b",
    "CN=a\\;b",
    "CN=\\ leading",
    "CN=trailing\\ ",
    "CN=\\#hash",
    "DC=net, DC=example, UID=jsmith",
    "CN=Lučić",
  ];
  strings.forEach(function (s) {
    var parsed = pki.x509.parseDn(s);
    check("round trip: " + s + " re-emits identically", parsed.dn === s);
    check("round trip: " + s + " carries encoded Name DER",
      Buffer.isBuffer(parsed.bytes) && parsed.bytes.length > 0);
    // Through the encoded form and back, which is the path a certificate takes.
    var again = pki.x509.parseDn(pki.x509.parseDn(parsed.dn).dn);
    check("round trip: " + s + " is stable through a second pass", again.dn === parsed.dn);
  });
}

// RFC 4514 sec. 2.4: a value may be given as '#' plus the hex of the AttributeValue DER,
// which is the only form that survives byte for byte, since the string form carries no
// ASN.1 string type.
function testHexValue() {
  var hex = b.utf8("hex").toString("hex");
  var parsed = pki.x509.parseDn("CN=#" + hex);
  check("a #-prefixed hex value decodes to the value its DER carries",
    parsed.rdns[0][0].value === "hex");
  check("and re-emits as the plain string, the DER having been read",
    parsed.dn === "CN=hex");
  // A PrintableString commonName, a type this toolkit does not choose by default, survives
  // the hex form exactly. That is the reason the form exists.
  var printable = b.printable("exact").toString("hex");
  var p2 = pki.x509.parseDn("CN=#" + printable);
  check("the hex form carries a string type the default encoding would not have chosen",
    pki.asn1.decode(p2.bytes).children[0].children[0].children[1].tagNumber === pki.asn1.TAGS.PRINTABLE_STRING);

  // The hex form carries the value's own DER, so it bypasses the encoder that would otherwise
  // apply an attribute's value constraints. It must not therefore become a way to build a name
  // this toolkit would refuse to build any other way, or to read back. Found by the fuzz target,
  // whose contract is that a dn this verb emits is a dn it can read.
  // VisibleString written as raw DER, which is what the hex form carries: tag 0x1a, then the
  // length, then the characters. "exct" is four, "US" is two.
  var visibleExct = "1a04" + Buffer.from("exct", "ascii").toString("hex");
  var printableExct = "1304" + Buffer.from("exct", "ascii").toString("hex");
  var printableUs = "1302" + Buffer.from("US", "ascii").toString("hex");
  check("a #hex countryName longer than two characters is refused (RFC 5280 sec. 4.1.2.4)",
    code(function () { pki.x509.parseDn("C=#" + printableExct); }) === "x509/bad-dn");
  check("a #hex countryName of exactly two characters in its own string type is accepted",
    pki.x509.parseDn("C=#" + printableUs).rdns[0][0].value === "US");
  check("every dn this verb emits is one it reads back",
    pki.x509.parseDn(pki.x509.parseDn("C=#" + printableUs).dn).dn === "C=US");
  check("a #hex countryName in a string type the module does not name is refused",
    code(function () { pki.x509.parseDn("C=#" + visibleExct.slice(0, 4) + Buffer.from("US", "ascii").toString("hex")); }) === "x509/bad-dn");

  // What follows a value must be a separator or the end of the string. The hex form ends at
  // the first non-hex character, so without this the character is simply swallowed and a name
  // an operator wrote wrong is accepted as a different name.
  var hexA = "#" + b.utf8("a").toString("hex");
  check("CONTROL: a comma after a #hex value separates", pki.x509.parseDn("CN=" + hexA + ",O=b").rdns.length === 2);
  check("CONTROL: a plus after a #hex value joins", pki.x509.parseDn("CN=" + hexA + "+O=b").rdns.length === 1);
  check("a semicolon after a #hex value is refused, not read as a separator",
    code(function () { pki.x509.parseDn("CN=" + hexA + ";O=b"); }) === "x509/bad-dn");
  check("a character that is not a separator after a #hex value is refused",
    code(function () { pki.x509.parseDn("CN=" + hexA + "!O=b"); }) === "x509/bad-dn");
  check("a space after a #hex value is refused rather than swallowed",
    code(function () { pki.x509.parseDn("CN=" + hexA + " O=b"); }) === "x509/bad-dn");

  check("an odd-length hex value is refused", code(function () { pki.x509.parseDn("CN=#abc"); }) === "x509/bad-dn");
  check("an empty hex value is refused", code(function () { pki.x509.parseDn("CN=#"); }) === "x509/bad-dn");
  // The hex branch must be held to every check the plain branch is held to, not just some of
  // them. An empty value is refused as a plain string, so an empty one that arrives as the DER
  // of a zero-length string is refused too, rather than emitting a dn that will not re-parse.
  check("a #hex value whose DER carries a zero-length string is refused",
    code(function () { pki.x509.parseDn("CN=#0c00"); }) === "x509/bad-dn");
  // The hex branch must be held to the attribute's alphabet too, not only its length. A
  // serialNumber is a PrintableString, whose alphabet has no underscore, so DER carrying one
  // is refused rather than encoded into a name whose own emitted string will not re-parse.
  // PrintableString DER carrying an underscore, which that alphabet has no room for. Written
  // as raw bytes because the builder refuses to produce it, which is the point.
  var printableUnderscore = "1303" + Buffer.from("a_b", "ascii").toString("hex");
  check("a #hex value carrying a character the attribute's string type forbids is refused",
    code(function () { pki.x509.parseDn("SERIALNUMBER=#" + printableUnderscore); }) === "x509/bad-dn");
  check("CONTROL: the same attribute accepts #hex DER its alphabet allows",
    pki.x509.parseDn("SERIALNUMBER=#" + b.printable("a-b").toString("hex")).rdns[0][0].value === "a-b");
  // For the five attributes RFC 5280 App. A.1 gives a single string type, the supplied DER
  // must BE that type. Otherwise the hex form becomes a way to put a UTF8String where the
  // module says PrintableString, or a non-string value where a string is required, which is
  // the same non-conformance the plain path cannot produce.
  var wrongType = [
    ["countryName as UTF8String", "C=#" + b.utf8("US").toString("hex")],
    ["serialNumber as UTF8String", "SERIALNUMBER=#" + b.utf8("12345").toString("hex")],
    ["domainComponent as UTF8String", "DC=#" + b.utf8("example").toString("hex")],
    ["emailAddress as PrintableString", "emailAddress=#" + b.printable("abc").toString("hex")],
    ["dnQualifier as UTF8String", "dnQualifier=#" + b.utf8("abc").toString("hex")],
    ["countryName as a non-string INTEGER", "C=#" + b.integer(5n).toString("hex")],
  ];
  wrongType.forEach(function (row) {
    check("a #hex value typed " + row[0] + " is refused", code(function () { pki.x509.parseDn(row[1]); }) === "x509/bad-dn");
  });
  check("CONTROL: each of those attributes accepts #hex DER of the type its module names",
    pki.x509.parseDn("C=#" + b.printable("US").toString("hex")).rdns[0][0].value === "US" &&
    pki.x509.parseDn("DC=#" + b.ia5("example").toString("hex")).rdns[0][0].value === "example" &&
    pki.x509.parseDn("dnQualifier=#" + b.printable("abc").toString("hex")).rdns[0][0].value === "abc");
  // CONTROL: a DirectoryString attribute still takes any of the types that CHOICE allows, so
  // the rule above is the five typed attributes and not a ban on the hex form.
  // A tag is a class, a constructed bit and a number, not a number alone. A context-specific
  // [19] is not a PrintableString however much its number matches, and a constructed one is
  // not a DER primitive string either.
  check("a #hex value with a context-specific tag whose number matches is refused",
    code(function () { pki.x509.parseDn("C=#9300"); }) === "x509/bad-dn");
  check("a #hex value with an application-class tag whose number matches is refused",
    code(function () { pki.x509.parseDn("C=#5302" + Buffer.from("US", "ascii").toString("hex")); }) === "x509/bad-dn");
  check("a #hex value with a constructed universal tag is refused",
    code(function () { pki.x509.parseDn("C=#3302" + Buffer.from("US", "ascii").toString("hex")); }) === "x509/bad-dn");

  check("CONTROL: a DirectoryString attribute accepts PrintableString or UTF8String DER",
    pki.x509.parseDn("CN=#" + b.printable("exact").toString("hex")).rdns[0][0].value === "exact" &&
    pki.x509.parseDn("CN=#" + b.utf8("exact").toString("hex")).rdns[0][0].value === "exact");
  // An attribute the toolkit publishes a short name for is one whose syntax it claims to know,
  // so its #hex DER is held to that syntax. RFC 5280 App. A.1 makes DirectoryString a CHOICE of
  // five string types, and a value that is none of them is not a DirectoryString however
  // well-formed its DER is.
  check("a DirectoryString attribute refuses #hex DER that is not a string at all",
    code(function () { pki.x509.parseDn("CN=#0500"); }) === "x509/bad-dn");
  check("a DirectoryString attribute refuses #hex DER of a string type outside the CHOICE",
    code(function () { pki.x509.parseDn("CN=#" + b.ia5("notachoice").toString("hex")); }) === "x509/bad-dn");
  // Every member of the CHOICE, by its universal tag: UTF8String 0x0c, PrintableString 0x13,
  // TeletexString 0x14, BMPString 0x1e (two octets per character).
  [["0c", "65"], ["13", "65"], ["14", "65"], ["1e", "0065"]].forEach(function (row) {
    var der = row[0] + (row[1].length / 2).toString(16).padStart(2, "0") + row[1];
    check("CONTROL: DirectoryString member with tag 0x" + row[0] + " is accepted",
      code(function () { pki.x509.parseDn("CN=#" + der); }) === "NO-THROW");
  });
  // An attribute whose syntax the toolkit does NOT claim to know keeps the opaque form, which
  // is the reason RFC 4514 sec. 2.4 defines it.
  var OPAQUE = "1.3.6.1.4.1.99999.4515";
  pki.oid.register(OPAQUE, "acmeOpaqueAttribute");
  check("an attribute with no published short name keeps an opaque #hex value",
    pki.x509.parseDn(OPAQUE + "=#0500").rdns[0][0].name === "acmeOpaqueAttribute");
  check("CONTROL: the equivalent plain empty value is refused the same way",
    code(function () { pki.x509.parseDn("CN="); }) === "x509/bad-dn");
  check("a hex value that is not one well-formed DER element is refused",
    code(function () { pki.x509.parseDn("CN=#0c0161ff"); }) === "x509/bad-dn");
}

// Each escape RFC 4514 sec. 2.4 defines, decoded one at a time, paired with a control that
// shows the unescaped character really does something different.
function testEscapes() {
  var pairs = [
    ["CN=a\\,b", "a,b"], ["CN=a\\+b", "a+b"], ["CN=a\\\"b", "a\"b"],
    ["CN=a\\\\b", "a\\b"], ["CN=a\\<b", "a<b"], ["CN=a\\>b", "a>b"],
    ["CN=a\\;b", "a;b"], ["CN=\\ lead", " lead"], ["CN=trail\\ ", "trail "],
    // A hex-pair escape. 0x41 is "A" and 0x4A is "J", used because a control byte cannot be
    // written into an ASCII source file.
    ["CN=a\\41b", "aAb"], ["CN=a\\4Ab", "aJb"], ["CN=a\\4ab", "aJb"],
  ];
  pairs.forEach(function (row) {
    check("escape " + row[0] + " decodes to its character", pki.x509.parseDn(row[0]).rdns[0][0].value === row[1]);
  });
  // A literal leading '#' round-trips through the sentinel the reader uses for it.
  check("an escaped leading # is the literal character", pki.x509.parseDn("CN=\\#hash").dn === "CN=\\#hash");

  // RFC 4514 sec. 3 says a run of "\XX" escapes carries UTF-8 octets. A byte sequence that is
  // not valid UTF-8 has no character to decode to, and a decoder that substitutes U+FFFD for
  // it turns distinct inputs into the same name: two operators writing different bytes would
  // get certificates whose subjects compare equal. Refuse instead.
  var badUtf8 = [
    ["a lone continuation-range byte", "CN=\\ff"],
    ["a different lone byte, which must not collapse onto the first", "CN=\\fe"],
    ["a truncated two-byte sequence", "CN=\\c3\\28"],
    ["a surrogate half, which UTF-8 never encodes", "CN=\\ed\\a0\\80"],
    ["an invalid byte between valid characters", "CN=a\\ffb"],
    ["an over-long encoding of NUL", "CN=\\c0\\80"],
  ];
  badUtf8.forEach(function (row) {
    check("a hex escape run that is not valid UTF-8 is refused: " + row[0],
      code(function () { pki.x509.parseDn(row[1]); }) === "x509/bad-dn");
  });
  // An escaped U+FEFF is one character of the value like any other. A decoder that drops a
  // leading one makes two different names encode identically, which is the same collapse the
  // invalid-UTF-8 refusal above exists to prevent.
  check("an escaped U+FEFF at the start of a value is kept",
    pki.x509.parseDn("CN=\\EF\\BB\\BFab").rdns[0][0].value.charCodeAt(0) === 0xfeff);
  check("an escaped U+FEFF in the middle of a value is kept",
    pki.x509.parseDn("CN=a\\EF\\BB\\BFb").rdns[0][0].value.length === 3);
  check("so a name with a leading U+FEFF does not encode to the same bytes as one without",
    !pki.x509.parseDn("CN=\\EF\\BB\\BFab").bytes.equals(pki.x509.parseDn("CN=ab").bytes));

  check("CONTROL: a valid multi-byte escape run is still accepted",
    pki.x509.parseDn("CN=\\C4\\8D").rdns[0][0].value === "č");
  check("CONTROL: a valid four-byte escape run is accepted",
    pki.x509.parseDn("CN=\\F0\\9F\\94\\92").rdns[0][0].value.length === 2);

  // RFC 4514 sec. 3's ABNF says which characters may appear unescaped. SUTF1 excludes NUL,
  // '"', '<' and '>' everywhere in a value; LUTF1 additionally excludes a leading space and a
  // leading '#'; TUTF1 additionally excludes a trailing space. A parser that accepts them
  // unescaped turns a mis-quoted config line into a certificate naming a different subject
  // than the operator wrote, which is why each is a refusal rather than a repair.
  function chr(c) { return String.fromCharCode(c); }
  // The semicolon is in this set, not in the separator set: RFC 4514 sec. 3 writes
  // `distinguishedName = [ relativeDistinguishedName *( COMMA relativeDistinguishedName ) ]`,
  // with COMMA being %x2C alone, and names SEMI only in the `escaped` production. RFC 1779
  // allowed it as a separator and this parser does not, so a legacy string carrying one is
  // refused rather than read as a different name than it says.
  var forbiddenAnywhere = [[0x00, "NUL"], [0x22, "a double quote"], [0x3b, "a semicolon"],
    [0x3c, "a less-than sign"], [0x3e, "a greater-than sign"]];
  forbiddenAnywhere.forEach(function (row) {
    check("unescaped " + row[1] + " inside a value is refused",
      code(function () { pki.x509.parseDn("CN=a" + chr(row[0]) + "b"); }) === "x509/bad-dn");
    check("unescaped " + row[1] + " at the start of a value is refused",
      code(function () { pki.x509.parseDn("CN=" + chr(row[0]) + "b"); }) === "x509/bad-dn");
    check("unescaped " + row[1] + " at the end of a value is refused",
      code(function () { pki.x509.parseDn("CN=a" + chr(row[0])); }) === "x509/bad-dn");
  });
  check("an unescaped leading space is refused (RFC 4514 LUTF1)",
    code(function () { pki.x509.parseDn("CN= lead"); }) === "x509/bad-dn");
  check("an unescaped trailing space is refused (RFC 4514 TUTF1)",
    code(function () { pki.x509.parseDn("CN=trail "); }) === "x509/bad-dn");
  check("an unescaped trailing space before a separator is refused",
    code(function () { pki.x509.parseDn("CN=trail ,O=b"); }) === "x509/bad-dn");
  // CONTROLS: escaped, every one of them is accepted, and a value that is only interior
  // spaces is untouched. Without these the refusals above could be the parser rejecting
  // ordinary names.
  check("CONTROL: the same characters escaped are all accepted",
    pki.x509.parseDn("CN=a\\\"b").rdns[0][0].value === "a\"b" &&
    pki.x509.parseDn("CN=a\\<b").rdns[0][0].value === "a<b" &&
    pki.x509.parseDn("CN=a\\>b").rdns[0][0].value === "a>b" &&
    pki.x509.parseDn("CN=\\ lead").rdns[0][0].value === " lead" &&
    pki.x509.parseDn("CN=trail\\ ").rdns[0][0].value === "trail ");
  check("CONTROL: spaces inside a value need no escape",
    pki.x509.parseDn("CN=J.  Smith").rdns[0][0].value === "J.  Smith");
  check("CONTROL: a space after the separator is the separator's, not the value's",
    pki.x509.parseDn("CN=a, O=b").rdns[1][0].value === "b");

  check("CONTROL: an unescaped comma splits into two RDNs", pki.x509.parseDn("CN=a,CN=b").rdns.length === 2);
  check("CONTROL: an unescaped plus makes one multi-valued RDN",
    pki.x509.parseDn("CN=a+OU=b").rdns.length === 1 && pki.x509.parseDn("CN=a+OU=b").rdns[0].length === 2);
  check("an unescaped semicolon is refused; RFC 4514 sec. 3 makes COMMA the only separator",
    code(function () { pki.x509.parseDn("CN=a;CN=b"); }) === "x509/bad-dn");
  check("CONTROL: an escaped semicolon is one character of the value",
    pki.x509.parseDn("CN=a\\;b").rdns[0][0].value === "a;b");
}

// A DN string reaches this verb from a config file or a command line, so the entry-point
// tier applies: throw, name the reason, and never hand back a name that quietly dropped a
// component a caller wrote.
function testRefusals() {
  var bad = [
    ["an empty attribute type", "=value"],
    ["no equals sign at all", "CN"],
    ["an unknown attribute name", "NOSUCHATTR=x"],
    ["a trailing separator", "CN=a,"],
    ["a trailing plus", "CN=a+"],
    ["a dangling escape at the end", "CN=a\\"],
    ["a truncated hex escape", "CN=a\\4"],
    ["a non-hex escape pair", "CN=a\\zz"],
    ["an escape of a character with no defined meaning", "CN=a\\qb"],
    ["an unregistered attribute OID", "1.3.6.1.4.1.99999.7=x"],
    ["the same attribute twice in one RDN", "CN=a+CN=b"],
  ];
  bad.forEach(function (row) {
    check(row[0] + " is refused with x509/bad-dn", code(function () { pki.x509.parseDn(row[1]); }) === "x509/bad-dn");
  });
  // The docstring promises exactly two codes, so no input may produce a third. A dotted type
  // that looks numeric but is not a canonical OID is the case that escaped: the registry's own
  // refusal carries an oid/ code, and a caller handling x509/bad-dn would miss it.
  var leaky = ["2.05.4.3=x", "2.5.04.3=x", "0.0=x", "3.1.1=x", "1.2.3.=x", ".1.2=x", "2.5.4.3.=x",
    "99999999999999999999.1=x", "1.=x", "1=x"];
  leaky.forEach(function (s) {
    check("a malformed dotted attribute type reports x509/bad-dn, not another domain: " + s,
      code(function () { pki.x509.parseDn(s); }) === "x509/bad-dn");
  });
  check("CONTROL: a canonical dotted attribute type still resolves",
    pki.x509.parseDn("2.5.4.3=x").rdns[0][0].name === "commonName");

  // A #hex value can be well-formed DER on its own and still push the assembled Name past the
  // decoder's nesting cap. That decode happens after every attribute has been accepted, so it
  // is the last place a code can escape the contract.
  var nested = "020101";
  for (var d = 0; d < 62; d++) nested = "30" + (nested.length / 2).toString(16).padStart(2, "0") + nested;
  check("a #hex value that pushes the assembled Name past the depth cap reports x509/bad-dn",
    code(function () { pki.x509.parseDn("clearance=#" + nested); }) === "x509/bad-dn");

  check("a non-string input is refused with x509/bad-input", code(function () { pki.x509.parseDn(42); }) === "x509/bad-input");
  check("a null input is refused with x509/bad-input", code(function () { pki.x509.parseDn(null); }) === "x509/bad-input");
  check("the empty string is a name with no RDNs, which RFC 4514 sec. 3 allows",
    pki.x509.parseDn("").rdns.length === 0 && pki.x509.parseDn("").dn === "");
}

// An attribute type may be written as a dotted OID, and the registry is the escape hatch for
// one this toolkit does not know: register it, and the same string parses.
function testDottedOidType() {
  check("a registered attribute written as its dotted OID parses",
    pki.x509.parseDn("2.5.4.3=viaoid").rdns[0][0].name === "commonName");
  // RFC 4514 sec. 3 takes its attribute descriptor from RFC 4512, where a descriptor is
  // case-insensitive. A name from another producer that spells one differently is the same
  // name, so it must parse rather than be refused as unknown.
  ["CN", "cn", "Cn", "commonName", "commonname", "COMMONNAME", "CoMmOnNaMe"].forEach(function (spelling) {
    check("the attribute descriptor " + spelling + " resolves to commonName",
      pki.x509.parseDn(spelling + "=a").rdns[0][0].name === "commonName");
  });
  check("a long descriptor in any case emits the canonical short name",
    pki.x509.parseDn("COMMONNAME=a").dn === "CN=a");
  check("CONTROL: a descriptor that is not an attribute at all is still refused",
    code(function () { pki.x509.parseDn("NOTANATTRIBUTE=a"); }) === "x509/bad-dn");
  var DOTTED = "1.3.6.1.4.1.99999.4514";
  check("CONTROL: an unregistered attribute OID is refused before registering it",
    code(function () { pki.x509.parseDn(DOTTED + "=x"); }) === "x509/bad-dn");
  pki.oid.register(DOTTED, "acmeDnTestAttribute");
  check("registering the OID makes the same string parse",
    pki.x509.parseDn(DOTTED + "=x").rdns[0][0].name === "acmeDnTestAttribute");

  // A registry name is free-form, and RFC 4512's descriptor grammar is not: it admits letters,
  // digits and hyphens only. A name outside it cannot be written into a dn string that parses,
  // so the dotted OID is emitted instead. Otherwise the emitted string is one this verb, and
  // any other RFC 4514 reader, refuses.
  var UNDERSCORED = "1.3.6.1.4.1.99999.4516";
  pki.oid.register(UNDERSCORED, "acme_underscored_attribute");
  var custom = pki.x509.parseDn(UNDERSCORED + "=hello");
  check("an attribute whose registered name is not a valid descriptor emits its dotted OID",
    custom.dn === UNDERSCORED + "=hello");
  check("and the emitted string parses back to the same attribute",
    pki.x509.parseDn(custom.dn).rdns[0][0].name === "acme_underscored_attribute");
  check("and to the identical encoded Name", pki.x509.parseDn(custom.dn).bytes.equals(custom.bytes));
}

// Every short name the public DN_SHORT table publishes must be one this verb can read and
// the builder can encode. A table naming an attribute nothing can produce is a broken
// promise on the public surface, which is what this set was before.
function testEveryPublishedShortNameWorks() {
  var shortNames = pki.C.NAMES.DN_SHORT;
  var attrs = Object.keys(shortNames);
  check("the published short-name table is non-empty", attrs.length > 0);
  attrs.forEach(function (attr) {
    check(attr + " resolves through the OID registry", typeof pki.oid.byName(attr) === "string");
    // The two country attributes are PrintableString SIZE(2); everything else takes any value.
    var value = (attr === "countryName" || attr === "jurisdictionCountryName") ? "US" : "x";
    var parsed;
    try { parsed = pki.x509.parseDn(shortNames[attr] + "=" + value); }
    catch (_e) { parsed = null; }
    check("a name written with the published short name " + shortNames[attr] + " parses",
      parsed !== null && parsed.rdns[0][0].name === attr);
  });
}

// RFC 5280 Appendix A.1 gives five distinguished-name attributes a string type that is NOT
// DirectoryString, and the encoder must use the one the module names: a value encoded as
// UTF8String where the module says PrintableString is a non-conforming certificate, and the
// alphabet restriction that comes with the type is lost with it.
function testAttributeStringTypes() {
  var TAGS = pki.asn1.TAGS;
  var typed = [
    ["countryName", "US", TAGS.PRINTABLE_STRING],
    // The CA/Browser Forum EV profile types the jurisdiction country the same way X.520 types
    // countryName. Oracle: OpenSSL encodes it PrintableString and refuses a longer value with
    // "string too long: maxsize=2"; its two jurisdiction siblings are DirectoryString.
    ["jurisdictionCountryName", "US", TAGS.PRINTABLE_STRING],
    ["distinguishedNameQualifier", "abc", TAGS.PRINTABLE_STRING],
    ["serialNumber", "12345", TAGS.PRINTABLE_STRING],
    ["emailAddress", "a@b.example", TAGS.IA5_STRING],
    ["domainComponent", "example", TAGS.IA5_STRING],
  ];
  typed.forEach(function (row) {
    var parsed = pki.x509.parseDn(pki.C.NAMES.DN_SHORT[row[0]] + "=" + row[1]);
    var valueNode = pki.asn1.decode(parsed.bytes).children[0].children[0].children[1];
    check(row[0] + " encodes as the string type RFC 5280 App. A.1 names", valueNode.tagNumber === row[2]);
  });
  // CONTROL: an attribute the module defines as DirectoryString still takes UTF8String, so the
  // assertions above are about those five and not about the encoder changing wholesale.
  check("a jurisdictionCountryName longer than two characters is refused",
    code(function () { pki.x509.parseDn("jurisdictionC=Japan"); }) === "x509/bad-dn");
  check("CONTROL: a two-character jurisdictionCountryName is accepted",
    pki.x509.parseDn("jurisdictionC=US").rdns[0][0].value === "US");
  ["commonName", "organizationName", "organizationalUnitName", "localityName",
    "jurisdictionStateOrProvinceName", "jurisdictionLocalityName"].forEach(function (attr) {
    var parsed = pki.x509.parseDn(pki.C.NAMES.DN_SHORT[attr] + "=value");
    var valueNode = pki.asn1.decode(parsed.bytes).children[0].children[0].children[1];
    check("CONTROL: " + attr + " is a DirectoryString and stays UTF8String", valueNode.tagNumber === TAGS.UTF8_STRING);
  });

  // The type carries an alphabet, so a character outside it is refused rather than encoded
  // into a string type that cannot hold it.
  check("a PrintableString attribute refuses a character outside its alphabet",
    code(function () { pki.x509.parseDn("dnQualifier=a_b"); }) === "x509/bad-dn");
  check("a serialNumber refuses a character outside the PrintableString alphabet",
    code(function () { pki.x509.parseDn("SERIALNUMBER=a_b"); }) === "x509/bad-dn");
  check("an IA5String attribute refuses a non-ASCII character",
    code(function () { pki.x509.parseDn("DC=exémple"); }) === "x509/bad-dn");
  check("CONTROL: the same attributes accept a value their alphabet allows",
    pki.x509.parseDn("dnQualifier=abc").rdns[0][0].value === "abc" &&
    pki.x509.parseDn("DC=example").rdns[0][0].value === "example");
  // CONTROL: a DirectoryString attribute still takes the character the others refuse.
  check("CONTROL: a DirectoryString attribute accepts non-ASCII",
    pki.x509.parseDn("CN=exémple").rdns[0][0].value === "exémple");
}

// The parsed name is usable where a built name is.
function testFeedsTheBuilder() {
  var parsed = pki.x509.parseDn("C=US, O=Example Inc, CN=leaf");
  check("the encoded Name is valid DER a builder accepts",
    pki.asn1.decode(parsed.bytes).tagNumber === pki.asn1.TAGS.SEQUENCE);
  check("re-parsing the emitted string yields the identical DER",
    pki.x509.parseDn(parsed.dn).bytes.equals(parsed.bytes));
}

// The builder takes the same two sentinel forms, and a caller can hand it one directly rather
// than through parseDn. A malformed one must be a typed refusal there too: an untyped throw
// out of a builder is the one outcome the error contract does not allow, and parseDn's own
// catch would hide it from every vector above.
async function testBuilderRejectsBadSentinelValues() {
  var kp = require("node:crypto").generateKeyPairSync("ed25519");
  var keys = {
    key: kp.privateKey.export({ format: "der", type: "pkcs8" }),
    spki: kp.publicKey.export({ format: "der", type: "spki" }),
  };
  var base = { subjectPublicKey: keys.spki, notBefore: new Date(Date.UTC(2026, 0, 1)), notAfter: new Date(Date.UTC(2027, 0, 1)) };
  var bad = [
    ["a #hex value that is not hexadecimal", "#zz"],
    ["a #hex value with an odd digit count", "#abc"],
    ["a #hex value carrying trailing DER", "#0c0161ff"],
    ["an empty #hex value", "#"],
  ];
  for (var i = 0; i < bad.length; i++) {
    var caught = null;
    try {
      await pki.x509.sign({ subject: [{ commonName: bad[i][1] }], subjectPublicKey: base.subjectPublicKey,
        notBefore: base.notBefore, notAfter: base.notAfter }, { key: keys.key });
    } catch (e) { caught = e; }
    check("x509.sign refuses " + bad[i][0] + " with a typed error, not a TypeError",
      caught !== null && caught instanceof pki.errors.PkiError);
    check("and that error names the name as the fault: " + bad[i][0],
      caught !== null && typeof caught.code === "string" && caught.code.indexOf("x509/") === 0);
  }
  // CONTROL: the same door with a well-formed #hex value issues a certificate.
  var ok = await pki.x509.sign({ subject: [{ commonName: "#" + b.utf8("hexname").toString("hex") }],
    subjectPublicKey: base.subjectPublicKey, notBefore: base.notBefore, notAfter: base.notAfter }, { key: keys.key });
  check("CONTROL: a well-formed #hex subject value issues, and reads back as its string",
    pki.schema.x509.parse(ok).subject.dn === "CN=hexname");
}

async function run() {
  testRfcExamples();
  testComponentOrder();
  testRoundTrip();
  testHexValue();
  testEscapes();
  testRefusals();
  testDottedOidType();
  testEveryPublishedShortNameWorks();
  testAttributeStringTypes();
  testFeedsTheBuilder();
  await testBuilderRejectsBadSentinelValues();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
