// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- the RFC 7512 PKCS #11 URI, parsed and formatted.
 *
 * The URI names a token and an object on it, which is how an operator points a tool at a
 * key in a hardware security module without naming a file. The vectors are derived from
 * the RFC's own ABNF and its MUST clauses: what the path and query may carry, what may
 * appear once, which characters may stand unencoded in which component, and what the two
 * numeric attributes mean.
 */

var helpers = require("../helpers");
var pki = helpers.pki;
var check = helpers.check;

function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return (e && e.code) || e.name; } }
function parse(uri) { return pki.pkcs11.parseUri(uri); }
function parseCode(uri) { return code(function () { return parse(uri); }); }

// ---- ACCEPT: the shapes the ABNF names --------------------------------
function testAcceptsTheAbnf() {
  check("1. the empty path is a URI on its own", parse("pkcs11:").path.token === undefined);
  check("2. a single path attribute", parse("pkcs11:token=The%20Software%20PKCS%2311%20Softtoken").path.token ===
    "The Software PKCS#11 Softtoken");
  check("3. path attributes are separated by a semicolon", (function () {
    var u = parse("pkcs11:token=A;manufacturer=B;serial=C;model=D");
    return u.path.token === "A" && u.path.manufacturer === "B" && u.path.serial === "C" && u.path.model === "D";
  })());
  check("4. the library attributes", (function () {
    var u = parse("pkcs11:library-manufacturer=M;library-description=D");
    return u.path.libraryManufacturer === "M" && u.path.libraryDescription === "D";
  })());
  check("5. the slot attributes", (function () {
    var u = parse("pkcs11:slot-manufacturer=M;slot-description=D;slot-id=42");
    return u.path.slotManufacturer === "M" && u.path.slotDescription === "D" && u.path.slotId === 42;
  })());
  check("6. object and type", (function () {
    var u = parse("pkcs11:object=my-key;type=private");
    return u.path.object === "my-key" && u.path.type === "private";
  })());
  check("7. every type the ABNF enumerates is accepted",
    ["public", "private", "cert", "secret-key", "data"].every(function (t) {
      return parse("pkcs11:type=" + t).path.type === t;
    }));
  check("8. a query component", (function () {
    var u = parse("pkcs11:token=A?module-name=mymodule");
    return u.path.token === "A" && u.query.moduleName === "mymodule";
  })());
  check("9. query attributes are separated by an ampersand", (function () {
    var u = parse("pkcs11:?module-name=a&pin-source=file:/etc/pin");
    return u.query.moduleName === "a" && u.query.pinSource === "file:/etc/pin";
  })());
  check("10. a vendor attribute in the path is kept under its own name",
    parse("pkcs11:vendor_x-attr=1").vendorPath["vendor_x-attr"] === "1");
  // The query component carries a vendor attribute as a list, because sec. 2.4 lets one repeat.
  check("11. a vendor attribute in the query is kept separately",
    parse("pkcs11:?vendor-q=1").vendorQuery["vendor-q"][0] === "1");
  check("12. the scheme is case-insensitive (RFC 3986 sec. 3.1)",
    parse("PKCS11:token=A").path.token === "A");
}

// ---- the two numeric attributes ---------------------------------------
function testNumericAttributes() {
  check("13. library-version takes M.N", (function () {
    var v = parse("pkcs11:library-version=2.30").path.libraryVersion;
    return v.major === 2 && v.minor === 30;
  })());
  check("14. library-version M alone means minor 0", (function () {
    var v = parse("pkcs11:library-version=3").path.libraryVersion;
    return v.major === 3 && v.minor === 0;
  })());
  check("15. a library-version with no major is refused",
    parseCode("pkcs11:library-version=.5") === "pkcs11/bad-uri");
  check("16. a non-decimal library-version is refused",
    parseCode("pkcs11:library-version=2.x") === "pkcs11/bad-uri");
  check("17. slot-id is a decimal number compared numerically (sec. 2.6)",
    parse("pkcs11:slot-id=0").path.slotId === 0);
  check("18. a non-decimal slot-id is refused", parseCode("pkcs11:slot-id=1a") === "pkcs11/bad-uri");
  check("19. a negative slot-id is refused (the ABNF admits digits only)",
    parseCode("pkcs11:slot-id=-1") === "pkcs11/bad-uri");
}

// ---- the id attribute carries bytes, not text --------------------------
function testIdIsBytes() {
  var id = parse("pkcs11:id=%01%02%FE").path.id;
  check("20. id is decoded to bytes", Buffer.isBuffer(id) && id.equals(Buffer.from([1, 2, 0xfe])));
  check("21. id round-trips as uppercase percent-encoding (sec. 2.3)",
    pki.pkcs11.formatUri({ path: { id: Buffer.from([1, 2, 0xfe]) } }) === "pkcs11:id=%01%02%FE");
  check("22. a lowercase escape parses to the same bytes",
    parse("pkcs11:id=%fe").path.id.equals(Buffer.from([0xfe])));
  check("23. and formats back uppercase, so two URIs for one id compare equal",
    pki.pkcs11.formatUri(parse("pkcs11:id=%fe")) === pki.pkcs11.formatUri(parse("pkcs11:id=%FE")));
}

// ---- REFUSE: the MUST NOT clauses --------------------------------------
function testRefusesWhatTheRfcRefuses() {
  check("24. a duplicate path attribute is refused (sec. 2.3)",
    parseCode("pkcs11:token=A;token=B") === "pkcs11/duplicate-attribute");
  check("25. a duplicate vendor path attribute is refused too",
    parseCode("pkcs11:v-a=1;v-a=2") === "pkcs11/duplicate-attribute");
  check("26. a duplicate module attribute is refused (sec. 2.4)",
    parseCode("pkcs11:?module-name=a&module-name=b") === "pkcs11/duplicate-attribute");
  check("27. pin-source and pin-value together are refused (sec. 2.4)",
    parseCode("pkcs11:?pin-source=file:/p&pin-value=1234") === "pkcs11/conflicting-pin");
  check("28. a relative module-path is refused (sec. 2.4)",
    parseCode("pkcs11:?module-path=lib/mymodule.so") === "pkcs11/relative-module-path");
  check("29. CONTROL: an absolute module-path is accepted",
    parse("pkcs11:?module-path=/usr/lib/mymodule.so").query.modulePath === "/usr/lib/mymodule.so");
  check("30. a type outside the enumeration is refused",
    parseCode("pkcs11:type=keypair") === "pkcs11/bad-uri");
  check("31. another scheme is refused", parseCode("pkcs12:token=A") === "pkcs11/bad-uri");
  check("32. a bare string with no scheme is refused", parseCode("token=A") === "pkcs11/bad-uri");
}

// ---- percent-encoding, per component -----------------------------------
function testPercentEncoding() {
  check("33. a truncated escape is refused", parseCode("pkcs11:token=%4") === "pkcs11/bad-escape");
  check("34. a non-hex escape is refused", parseCode("pkcs11:token=%zz") === "pkcs11/bad-escape");
  check("35. a reserved character the path admits stands unencoded (sec. 2.3)",
    parse("pkcs11:token=a:b[c]d@e!f$g'h(i)j*k+l,m=n").path.token === "a:b[c]d@e!f$g'h(i)j*k+l,m=n");
  check("36. an ampersand stands unencoded in the path",
    parse("pkcs11:token=a&b").path.token === "a&b");
  check("37. a slash must be encoded in the path", parseCode("pkcs11:token=a/b") === "pkcs11/bad-uri");
  check("38. and parses when it is", parse("pkcs11:token=a%2Fb").path.token === "a/b");
  check("39. a query value admits the slash, question mark and vertical bar (sec. 2.4)",
    parse("pkcs11:?module-path=/a?b|c").query.modulePath === "/a?b|c");
  check("40. a number sign is always encoded", parseCode("pkcs11:token=a#b") === "pkcs11/bad-uri");
  check("41. a space must be encoded", parseCode("pkcs11:token=a b") === "pkcs11/bad-uri");
  check("42. a value is decoded as UTF-8 (sec. 2.3)",
    parse("pkcs11:token=%C3%A9").path.token === "é");
  check("43. an escape that is not valid UTF-8 is refused",
    parseCode("pkcs11:token=%FF%FF") === "pkcs11/bad-encoding");
}

// ---- formatting is the inverse -----------------------------------------
function testFormatIsTheInverse() {
  var uris = [
    "pkcs11:",
    "pkcs11:token=A;manufacturer=B;serial=C;model=D",
    "pkcs11:library-manufacturer=M;library-description=D;library-version=2.30",
    "pkcs11:object=my-key;type=private;id=%01%02",
    "pkcs11:slot-manufacturer=M;slot-description=D;slot-id=7",
    "pkcs11:token=A?module-name=mymodule",
    "pkcs11:?pin-value=1234",
    "pkcs11:token=The%20Software%20PKCS%2311%20Softtoken",
  ];
  var broken = [];
  uris.forEach(function (uri) {
    var out = pki.pkcs11.formatUri(parse(uri));
    if (out !== uri) broken.push(uri + " -> " + out);
  });
  check("44. every URI formats back to itself (" + broken.join("; ") + ")", broken.length === 0);

  check("45. formatting encodes what the component does not admit",
    pki.pkcs11.formatUri({ path: { token: "a/b c#d" } }) === "pkcs11:token=a%2Fb%20c%23d");
  check("46. a query value keeps the characters its component admits",
    pki.pkcs11.formatUri({ query: { modulePath: "/a?b|c" } }) === "pkcs11:?module-path=/a?b|c");
  check("47. an ampersand in a query value is encoded, since it separates attributes",
    pki.pkcs11.formatUri({ query: { pinValue: "a&b" } }) === "pkcs11:?pin-value=a%26b");
  check("48. formatting refuses pin-source with pin-value the way parsing does",
    code(function () { return pki.pkcs11.formatUri({ query: { pinSource: "file:/p", pinValue: "1" } }); }) ===
      "pkcs11/conflicting-pin");
  check("49. formatting refuses a type outside the enumeration",
    code(function () { return pki.pkcs11.formatUri({ path: { type: "keypair" } }); }) === "pkcs11/bad-input");
  check("50. formatting refuses a relative module-path",
    code(function () { return pki.pkcs11.formatUri({ query: { modulePath: "lib/m.so" } }); }) ===
      "pkcs11/relative-module-path");
}

// ---- the caller's object is not trusted --------------------------------
function testCallerInput() {
  check("51. a non-string URI is refused", parseCode(Buffer.from("pkcs11:")) === "pkcs11/bad-input");
  check("52. an unknown field in the format record is named",
    code(function () { return pki.pkcs11.formatUri({ path: { tokn: "A" } }); }) === "pkcs11/bad-input");
  check("53. an unknown top-level field is named",
    code(function () { return pki.pkcs11.formatUri({ paths: {} }); }) === "pkcs11/bad-input");
  check("54. the parsed record carries no prototype, so a computed read answers from it alone",
    Object.getPrototypeOf(parse("pkcs11:token=A").path) === null);
  check("55. a value named on Object.prototype does not become an attribute", (function () {
    Object.prototype.token = "planted";
    try { return parse("pkcs11:").path.token === undefined; }
    finally { delete Object.prototype.token; }
  })());
  check("55a. a record that is not there is refused",
    code(function () { return pki.pkcs11.formatUri(null); }) === "pkcs11/bad-input");
  check("55b. a URI string in place of the record is refused, the two directions not being one verb",
    code(function () { return pki.pkcs11.formatUri("pkcs11:token=A"); }) === "pkcs11/bad-input");
  check("55c. and so are bytes, which carry own indices rather than attribute names",
    code(function () { return pki.pkcs11.formatUri(Buffer.from("pkcs11:")); }) === "pkcs11/bad-input");
  check("55d. a component that is not an object is refused",
    code(function () { return pki.pkcs11.formatUri({ path: "token=A" }); }) === "pkcs11/bad-input");
  check("55e. a vendor component that is not an object is refused",
    code(function () { return pki.pkcs11.formatUri({ vendorPath: "x=1" }); }) === "pkcs11/bad-input");
  check("55f. a vendor attribute with no name is refused",
    code(function () { return pki.pkcs11.formatUri({ vendorPath: { "": "v" } }); }) === "pkcs11/bad-input");
  check("55g. an attribute run with no value separator is refused",
    parseCode("pkcs11:token") === "pkcs11/bad-uri");
  check("55h. a number past what this toolkit reads is refused while it is being read",
    parseCode("pkcs11:slot-id=99999999999999999999") === "pkcs11/bad-uri");
  // A lone surrogate has no UTF-8 form. Writing the replacement character for it would put a
  // name in the URI that the caller never asked for.
  // A text attribute carries what the URI carries, which is a string. Coercing anything else
  // writes a value the caller never named: an object reaches the URI as its default string form,
  // and a list as its members joined with a comma, both of which read back as one value.
  check("55j. a text attribute given an object is refused",
    code(function () { return pki.pkcs11.formatUri({ path: { token: { name: "A" } } }); }) === "pkcs11/bad-input");
  check("55k. a text attribute given a list is refused",
    code(function () { return pki.pkcs11.formatUri({ path: { token: ["a", "b"] } }); }) === "pkcs11/bad-input");
  check("55l. and so is a number, the attribute not being one",
    code(function () { return pki.pkcs11.formatUri({ path: { token: 7 } }); }) === "pkcs11/bad-input");
  check("55m. a vendor path attribute is held to the same rule",
    code(function () { return pki.pkcs11.formatUri({ vendorPath: { "x-v": ["a", "b"] } }); }) === "pkcs11/bad-input");
  check("55n. and so is each value in a vendor query attribute's list",
    code(function () { return pki.pkcs11.formatUri({ vendorQuery: { "x-v": [{ a: 1 }] } }); }) === "pkcs11/bad-input");
  check("55o. a module-path given a non-string is refused before it is measured for being absolute",
    code(function () { return pki.pkcs11.formatUri({ query: { modulePath: ["/usr/lib/x.so"] } }); }) === "pkcs11/bad-input");
  check("55p. a type given a non-string is refused",
    code(function () { return pki.pkcs11.formatUri({ path: { type: ["private"] } }); }) === "pkcs11/bad-input");
  check("55q. CONTROL: the string forms of all of those are written",
    pki.pkcs11.formatUri({ path: { token: "7", type: "private" }, vendorPath: { "x-v": "a" },
      query: { modulePath: "/usr/lib/x.so" }, vendorQuery: { "y-v": ["b"] } }) ===
      "pkcs11:token=7;type=private;x-v=a?module-path=/usr/lib/x.so&y-v=b");
  check("55i. a value carrying an unpaired surrogate is refused rather than replaced",
    code(function () {
      return pki.pkcs11.formatUri({ path: { token: String.fromCharCode(0xD800) } });
    }) === "pkcs11/bad-input");
}

// ---- a vendor name cannot smuggle in a standard attribute --------------
function testVendorNamesAreHeldToTheGrammar() {
  check("56. a vendor name carrying a delimiter is refused rather than written out",
    code(function () { return pki.pkcs11.formatUri({ vendorPath: { "x=ok;type": "private" } }); }) === "pkcs11/bad-input");
  check("57. a vendor name the standard table owns is refused",
    code(function () { return pki.pkcs11.formatUri({ vendorPath: { "token": "A" } }) ; }) === "pkcs11/bad-input");
  check("58. and so is one the query's table owns",
    code(function () { return pki.pkcs11.formatUri({ vendorQuery: { "module-path": "relative.so" } }); }) === "pkcs11/bad-input");
  check("59. a second pin attribute cannot arrive through the vendor door",
    code(function () { return pki.pkcs11.formatUri({ query: { pinSource: "file:/p" }, vendorQuery: { "pin-value": "1" } }); }) ===
      "pkcs11/bad-input");
  check("60. CONTROL: a well-formed vendor name is written",
    pki.pkcs11.formatUri({ vendorPath: { "x-vendor_1": "v" } }) === "pkcs11:x-vendor_1=v");
  check("61. a vendor name the standard table owns is refused on the way in too",
    parseCode("pkcs11:?vendor=1&module-name=a") === "NO-THROW");
}

// ---- an empty attribute between delimiters -----------------------------
function testEmptyAttributeRuns() {
  check("62. an empty run between two path attributes is refused",
    parseCode("pkcs11:token=A;;type=private") === "pkcs11/bad-uri");
  check("63. a trailing semicolon is refused", parseCode("pkcs11:token=A;") === "pkcs11/bad-uri");
  check("64. a lone semicolon is refused", parseCode("pkcs11:;") === "pkcs11/bad-uri");
  check("65. an empty run in the query is refused", parseCode("pkcs11:?&") === "pkcs11/bad-uri");
  check("66. CONTROL: the empty path is still a URI", parseCode("pkcs11:") === "NO-THROW");
  check("67. CONTROL: an empty query component is still a URI", parseCode("pkcs11:token=A?") === "NO-THROW");
}

// ---- the formatter writes only what the parser reads -------------------
function testFormatterNumericBounds() {
  check("68. a slot-id beyond the safe-integer range is refused rather than written",
    code(function () { return pki.pkcs11.formatUri({ path: { slotId: 9007199254740992 } }); }) === "pkcs11/bad-input");
  check("69. a library-version beyond it is refused too",
    code(function () { return pki.pkcs11.formatUri({ path: { libraryVersion: { major: 9007199254740992, minor: 0 } } }); }) ===
      "pkcs11/bad-input");
  check("70. CONTROL: the largest slot-id the parser reads is written",
    pki.pkcs11.formatUri({ path: { slotId: 9007199254740991 } }) === "pkcs11:slot-id=9007199254740991");
  check("71. and the parser reads it back",
    parse("pkcs11:slot-id=9007199254740991").path.slotId === 9007199254740991);
}

// ---- the worked example of RFC 7512 sec. 3 ------------------------------
function testTheRfcsOwnExample() {
  var uri = "pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;" +
    "manufacturer=Snake%20Oil,%20Inc.;model=1.0;object=my-certificate;type=cert;" +
    "id=%69%95%3E%5C%F4%BD%EC%91;serial=?pin-source=file:/etc/token_pin";
  var u = parse(uri);
  check("72. the RFC's own example parses", u.path.token === "The Software PKCS#11 Softtoken");
  check("73. its manufacturer keeps the comma the path admits unencoded", u.path.manufacturer === "Snake Oil, Inc.");
  check("74. its id is eight bytes", u.path.id.length === 8 && u.path.id[0] === 0x69);
  check("75. its empty serial is an empty string, not an absent attribute", u.path.serial === "");
  check("76. its pin-source keeps the colon and slash the query admits", u.query.pinSource === "file:/etc/token_pin");
  // Writing is canonical rather than byte-preserving: attributes come out in the order the RFC
  // lists them, and the sec. 2.6 normalizations apply, so two URIs naming one object compare
  // equal as strings. What has to hold is that the canonical form is stable and reads back.
  var once = pki.pkcs11.formatUri(u);
  check("77. its canonical form reads back to the same record",
    pki.pkcs11.formatUri(parse(once)) === once);
  check("78. and carries every attribute the original did",
    once.indexOf("token=The%20Software%20PKCS%2311%20Softtoken") !== -1 &&
    once.indexOf("id=%69%95%3E%5C%F4%BD%EC%91") !== -1 &&
    once.indexOf("?pin-source=file:/etc/token_pin") !== -1);
}

// ---- the attributes whose ABNF admits no escape ------------------------
function testLiteralAttributesRefuseEscapes() {
  check("80. a percent-escape in type is refused, since its ABNF is literal alternatives",
    parseCode("pkcs11:type=%70ublic") === "pkcs11/bad-uri");
  check("81. a percent-escape in slot-id is refused, since its ABNF is 1*DIGIT",
    parseCode("pkcs11:slot-id=%31") === "pkcs11/bad-uri");
  check("82. a percent-escape in library-version is refused for the same reason",
    parseCode("pkcs11:library-version=%31%2E%32") === "pkcs11/bad-uri");
  check("83. CONTROL: the same values unescaped parse", (function () {
    var u = parse("pkcs11:type=public;slot-id=1;library-version=1.2");
    return u.path.type === "public" && u.path.slotId === 1 && u.path.libraryVersion.major === 1;
  })());
  // RFC 5234 sec. 2.3 makes an ABNF quoted literal case-insensitive, and RFC 7512 sec. 2.6 asks a
  // consumer to compare after case normalization, so the spelling is accepted and canonicalized.
  check("84. a type is read case-insensitively", parse("pkcs11:type=PUBLIC").path.type === "public");
  check("85. and canonicalizes to one spelling",
    pki.pkcs11.formatUri(parse("pkcs11:type=Secret-Key")) === "pkcs11:type=secret-key");
  check("86. a type outside the enumeration is still refused whatever its case",
    parseCode("pkcs11:type=KEYPAIR") === "pkcs11/bad-uri");
}

// ---- a standard attribute is that attribute whatever case it arrives in -
function testStandardNamesAreCaseInsensitive() {
  check("94. a standard path attribute is read whatever case its name arrives in",
    parse("pkcs11:TOKEN=A").path.token === "A");
  check("95. and a standard query attribute the same way",
    parse("pkcs11:?MODULE-NAME=a").query.moduleName === "a");
  check("96. so two spellings of one name are a duplicate",
    parseCode("pkcs11:token=A;TOKEN=B") === "pkcs11/duplicate-attribute");
  check("97. an uppercase module-path is held to the absolute-path rule",
    parseCode("pkcs11:?MODULE-PATH=relative.so") === "pkcs11/relative-module-path");
  check("98. an uppercase pin attribute is held to the pin-exclusivity rule",
    parseCode("pkcs11:?PIN-SOURCE=file:/pin&pin-value=1234") === "pkcs11/conflicting-pin");
  check("99. an uppercase type is held to the enumeration",
    parseCode("pkcs11:TYPE=keypair") === "pkcs11/bad-uri");
  check("100. and the name canonicalizes to the RFC's spelling",
    pki.pkcs11.formatUri(parse("pkcs11:TOKEN=A")) === "pkcs11:token=A");
  check("101. a vendor name that collides with a standard one in any case is refused",
    code(function () { return pki.pkcs11.formatUri({ vendorPath: { "TOKEN": "A" } }); }) === "pkcs11/bad-input");
  check("107. a vendor name is written in the one case the reader matches",
    pki.pkcs11.formatUri({ vendorPath: { "X-Vendor": "a" } }) === "pkcs11:x-vendor=a");
  check("108. so writing it and reading it back is stable",
    pki.pkcs11.formatUri(parse(pki.pkcs11.formatUri({ vendorPath: { "X-Vendor": "a" } }))) === "pkcs11:x-vendor=a");
  check("109. two vendor names that differ only in case are a duplicate, not two attributes",
    code(function () { return pki.pkcs11.formatUri({ vendorPath: { "FOO": "a", "foo": "b" } }); }) ===
      "pkcs11/duplicate-attribute");
  check("110. and the same in the query component",
    code(function () { return pki.pkcs11.formatUri({ vendorQuery: { "X": ["1"], "x": ["2"] } }); }) ===
      "pkcs11/duplicate-attribute");
  // Sorted by the name the URI carries, not the one the record happened to use, or a mixed-case
  // record would order differently from the URI it produces.
  check("120. vendor attributes are ordered by the name the URI carries",
    pki.pkcs11.formatUri({ vendorPath: { Z: "1", a: "2" } }) === "pkcs11:a=2;z=1");
  check("121. so a mixed-case record and its own output agree", (function () {
    var once = pki.pkcs11.formatUri({ vendorPath: { Z: "1", a: "2" } });
    return pki.pkcs11.formatUri(parse(once)) === once;
  })());
}

// ---- what may repeat, and where ----------------------------------------
function testRepeatedVendorQueryAttributes() {
  // sec. 2.4: "Aside from the query attributes defined in this document, duplicate (vendor)
  // attributes MAY be present in the URI query component". The path admits no duplicate at all.
  var u = parse("pkcs11:?x-vendor=one&x-vendor=two");
  check("122. a repeated vendor query attribute is carried, in the order it arrived",
    Array.isArray(u.vendorQuery["x-vendor"]) && u.vendorQuery["x-vendor"].length === 2 &&
    u.vendorQuery["x-vendor"][0] === "one" && u.vendorQuery["x-vendor"][1] === "two");
  check("123. a vendor query attribute that appears once is still a list of one",
    Array.isArray(parse("pkcs11:?x-vendor=one").vendorQuery["x-vendor"]));
  check("124. and it writes back to the same URI",
    pki.pkcs11.formatUri(parse("pkcs11:?x-vendor=one&x-vendor=two")) === "pkcs11:?x-vendor=one&x-vendor=two");
  check("125. a repeated vendor PATH attribute is still refused, the path admitting none",
    parseCode("pkcs11:x-vendor=one;x-vendor=two") === "pkcs11/duplicate-attribute");
  check("126. a repeated query attribute the RFC defines is still refused",
    parseCode("pkcs11:?module-name=a&module-name=b") === "pkcs11/duplicate-attribute");
  check("127. and so is a repeated pin attribute, which leaves which PIN applies undecided",
    parseCode("pkcs11:?pin-value=1&pin-value=2") === "pkcs11/duplicate-attribute");
  check("128. the formatter writes a list, and refuses a value that is not one",
    code(function () { return pki.pkcs11.formatUri({ vendorQuery: { "x-v": "one" } }); }) === "pkcs11/bad-input");
  check("129. CONTROL: a list writes each value",
    pki.pkcs11.formatUri({ vendorQuery: { "x-v": ["one", "two"] } }) === "pkcs11:?x-v=one&x-v=two");
  check("130. names are still ordered, and a name's own values keep their order",
    pki.pkcs11.formatUri({ vendorQuery: { "z-v": ["b", "a"], "a-v": ["c"] } }) ===
      "pkcs11:?a-v=c&z-v=b&z-v=a");
  // A name the caller wrote is an attribute the caller asked for. Writing the record without it
  // answers a different URI than the one that was asked for, and the caller is told neither.
  check("131. a vendor query attribute given an empty list is refused, not dropped",
    code(function () { return pki.pkcs11.formatUri({ vendorQuery: { "x-v": [] } }); }) === "pkcs11/bad-input");
  check("132. and it is refused beside attributes that do write",
    code(function () {
      return pki.pkcs11.formatUri({ query: { moduleName: "m" }, vendorQuery: { "x-v": [], "y-v": ["1"] } });
    }) === "pkcs11/bad-input");
  check("133. a vendor query attribute given no value is refused",
    code(function () { return pki.pkcs11.formatUri({ vendorQuery: { "x-v": null } }); }) === "pkcs11/bad-input");
  check("134. a vendor path attribute given no value is refused",
    code(function () { return pki.pkcs11.formatUri({ vendorPath: { "x-v": undefined } }); }) === "pkcs11/bad-input");
  check("135. CONTROL: the name is not written under any of those",
    pki.pkcs11.formatUri({ vendorQuery: { "x-v": [""] } }) === "pkcs11:?x-v=");
  check("136. a list with a value missing from it is refused, the others notwithstanding",
    code(function () { return pki.pkcs11.formatUri({ vendorQuery: { "x-v": ["a", null] } }); }) === "pkcs11/bad-input");
}

// ---- case folding is the ASCII fold the grammar is written in ----------
function testCaseFoldingIsAscii() {
  // U+212A KELVIN SIGN lowercases to "k" under Unicode, so a Unicode fold applied before the
  // grammar check would read a name with one in it as a standard attribute.
  var kelvin = "K";
  check("115. a name carrying a character outside the grammar is not folded into a standard one",
    parseCode("pkcs11:to" + kelvin + "en=A") !== "NO-THROW");
  check("116. nor into a vendor name", parseCode("pkcs11:x-" + kelvin + "=1") !== "NO-THROW");
  check("117. nor is the scheme itself folded", parseCode("p" + kelvin + "cs11:") !== "NO-THROW");
  check("118. nor a type value", parseCode("pkcs11:type=cert" + kelvin) !== "NO-THROW");
  check("119. CONTROL: the ASCII spellings of each still parse", (function () {
    return parse("PKCS11:toKen=A;TYPE=CERT;X-K=1").path.token === "A" &&
      parse("PKCS11:toKen=A;TYPE=CERT;X-K=1").path.type === "cert" &&
      parse("PKCS11:toKen=A;TYPE=CERT;X-K=1").vendorPath["x-k"] === "1";
  })());
}

// ---- a caller value is read once ---------------------------------------
function testCallerValuesAreCoercedOnce() {
  // A value whose toString answers differently on a second read would let the check see one
  // string and the URI carry another, which is how a relative module-path gets written out.
  // Such a value is refused now, so either outcome holds the property.
  var reads = 0;
  var shifting = { toString: function () { reads += 1; return reads === 1 ? "/absolute" : "relative"; } };
  var written = null, refusal = null;
  try { written = pki.pkcs11.formatUri({ query: { modulePath: shifting } }); }
  catch (e) { refusal = (e && e.code) || e.name; }
  check("111. a module-path read twice cannot become relative between the check and the URI (" +
    (written === null ? refusal : written) + ")",
    written === "pkcs11:?module-path=/absolute" || refusal === "pkcs11/bad-input");
  check("112. and the value was read at most once (" + reads + ")", reads <= 1);

  // A lone surrogate has no UTF-8 form; writing the replacement character for it would put a
  // different name in the URI than the caller asked for.
  // The record is read once too, not only each value: a value that runs code while one component
  // is written must not be able to add an attribute to a component written after it, which would
  // put a URI past a check that had already passed.
  var query = { pinSource: "a" };
  var lateArrival = {
    vendorPath: { x: { toString: function () { query.pinValue = "b"; return "v"; } } },
    query: query,
  };
  var out = null, thrown = null;
  try { out = pki.pkcs11.formatUri(lateArrival); }
  catch (e) { thrown = (e && e.code) || e.name; }
  check("115a. an attribute that appears mid-write does not reach the URI (" + (out === null ? thrown : out) + ")",
    thrown === "pkcs11/bad-input" || thrown === "pkcs11/conflicting-pin" ||
      (out !== null && out.indexOf("pin-value") === -1));
  check("115b. and whatever came out reads back",
    out === null || parseCode(out) === "NO-THROW");

  // The same one level down: a member of the version record is read once, so a getter cannot
  // answer inside the range for the check and outside it for the string.
  var majorReads = 0;
  var shiftingVersion = {
    get major() { majorReads += 1; return majorReads <= 2 ? 1 : 256; },
    minor: 0,
  };
  var vOut = null, vThrown = null;
  try { vOut = pki.pkcs11.formatUri({ path: { libraryVersion: shiftingVersion } }); }
  catch (e) { vThrown = (e && e.code) || e.name; }
  check("115c. a version member read twice cannot leave the range between the check and the URI (" +
    (vOut === null ? vThrown : vOut) + ")",
    vOut === "pkcs11:library-version=1.0" || vThrown === "pkcs11/bad-input");
  check("115d. and the member was read at most once (" + majorReads + ")", majorReads <= 1);

  check("113. a value with no UTF-8 form is refused rather than replaced",
    code(function () { return pki.pkcs11.formatUri({ path: { token: "\ud800" } }); }) === "pkcs11/bad-input");
  check("114. CONTROL: a value outside the basic plane is written",
    pki.pkcs11.formatUri({ path: { token: "🔑" } }) === "pkcs11:token=%F0%9F%94%91");
}

// ---- the library version is two one-byte numbers -----------------------
function testLibraryVersionIsTwoBytes() {
  check("102. a major above one byte is refused (sec. 2.3)",
    parseCode("pkcs11:library-version=256") === "pkcs11/bad-uri");
  check("103. a minor above one byte is refused too",
    parseCode("pkcs11:library-version=1.256") === "pkcs11/bad-uri");
  check("104. CONTROL: the largest version a token can report parses", (function () {
    var v = parse("pkcs11:library-version=255.255").path.libraryVersion;
    return v.major === 255 && v.minor === 255;
  })());
  check("105. the formatter refuses what the parser would",
    code(function () { return pki.pkcs11.formatUri({ path: { libraryVersion: { major: 256, minor: 0 } } }); }) ===
      "pkcs11/bad-input");
  check("106. and refuses an out-of-range minor as well",
    code(function () { return pki.pkcs11.formatUri({ path: { libraryVersion: { major: 1, minor: 256 } } }); }) ===
      "pkcs11/bad-input");
  check("106a. a version given as one number is refused, the attribute carrying two",
    code(function () { return pki.pkcs11.formatUri({ path: { libraryVersion: 3 } }); }) === "pkcs11/bad-input");
  check("106b. and so is one given as the string a URI would carry",
    code(function () { return pki.pkcs11.formatUri({ path: { libraryVersion: "3.0" } }); }) === "pkcs11/bad-input");
}

// ---- an absolute module path on every platform the toolkit runs on ------
function testAbsoluteModulePaths() {
  var absolute = [
    ["a POSIX path", "/usr/lib/softhsm/libsofthsm2.so"],
    ["a Windows drive path with forward slashes", "C:/Program%20Files/HSM/pkcs11.dll"],
    ["a Windows drive path with backslashes", "C:%5CProgram%20Files%5CHSM%5Cpkcs11.dll"],
    ["a UNC path", "%5C%5Cserver%5Cshare%5Cpkcs11.dll"],
  ];
  var refused = [];
  absolute.forEach(function (row) {
    var verdict = parseCode("pkcs11:?module-path=" + row[1]);
    if (verdict !== "NO-THROW") refused.push(row[0] + ": " + verdict);
  });
  check("87. an absolute module path is accepted on every platform (" + refused.join("; ") + ")",
    refused.length === 0);

  var relative = ["lib/pkcs11.so", "./pkcs11.so", "..%5Cpkcs11.dll", "pkcs11.dll", ""];
  var accepted = [];
  relative.forEach(function (value) {
    if (parseCode("pkcs11:?module-path=" + value) === "NO-THROW") accepted.push(JSON.stringify(value));
  });
  check("88. CONTROL: a relative module path is still refused (" + accepted.join("; ") + ")",
    accepted.length === 0);
  check("89. and the formatter refuses the same ones",
    code(function () { return pki.pkcs11.formatUri({ query: { modulePath: "C:relative.dll" } }); }) ===
      "pkcs11/relative-module-path");
  check("90. CONTROL: the formatter writes an absolute Windows path",
    pki.pkcs11.formatUri({ query: { modulePath: "C:\\HSM\\pkcs11.dll" } }) === "pkcs11:?module-path=C:%5CHSM%5Cpkcs11.dll");
}

// ---- normalization is what makes two URIs comparable -------------------
function testCanonicalization() {
  var pairs = [
    ["pkcs11:library-version=3", "pkcs11:library-version=3.0"],
    ["pkcs11:slot-id=0007", "pkcs11:slot-id=7"],
    ["pkcs11:id=a", "pkcs11:id=%61"],
    ["pkcs11:token=A?", "pkcs11:token=A"],
  ];
  var broken = [];
  pairs.forEach(function (pair) {
    var got = pki.pkcs11.formatUri(parse(pair[0]));
    if (got !== pair[1]) broken.push(pair[0] + " -> " + got + " (wanted " + pair[1] + ")");
    if (pki.pkcs11.formatUri(parse(got)) !== got) broken.push(got + " is not stable");
  });
  check("79. a URI normalizes to one canonical form, and that form is stable (" + broken.join("; ") + ")",
    broken.length === 0);

  // Vendor attributes are part of the canonical form too: two URIs carrying the same set in a
  // different order name the same object, so they have to compare equal as strings.
  check("91. vendor attributes are written in one order whatever order they arrived in",
    pki.pkcs11.formatUri(parse("pkcs11:x-two=2;x-one=1")) === pki.pkcs11.formatUri(parse("pkcs11:x-one=1;x-two=2")));
  check("92. and so are vendor query attributes",
    pki.pkcs11.formatUri(parse("pkcs11:?z-b=2&z-a=1")) === pki.pkcs11.formatUri(parse("pkcs11:?z-a=1&z-b=2")));
  check("93. CONTROL: both still carry every attribute",
    pki.pkcs11.formatUri(parse("pkcs11:x-two=2;x-one=1")) === "pkcs11:x-one=1;x-two=2");
}

function run() {
  testAcceptsTheAbnf();
  testNumericAttributes();
  testIdIsBytes();
  testRefusesWhatTheRfcRefuses();
  testPercentEncoding();
  testFormatIsTheInverse();
  testCallerInput();
  testVendorNamesAreHeldToTheGrammar();
  testEmptyAttributeRuns();
  testFormatterNumericBounds();
  testTheRfcsOwnExample();
  testLiteralAttributesRefuseEscapes();
  testStandardNamesAreCaseInsensitive();
  testRepeatedVendorQueryAttributes();
  testCaseFoldingIsAscii();
  testCallerValuesAreCoercedOnce();
  testLibraryVersionIsTwoBytes();
  testAbsoluteModulePaths();
  testCanonicalization();
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve().then(run).then(
    function () { console.log("CHECKS " + helpers.getChecks()); },
    function (e) { console.error(helpers.formatErr(e)); process.exit(1); }
  );
}
