// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// @internal

/** @internal The keys every verifier in this toolkit refuses: certificate keys whose private key is
 *  public, whether published or derivable from the public key. Each entry is the SHA-256 digest of
 *  the key's SubjectPublicKeyInfo in canonical form (the value `pki.trust.spkiDigest` returns), the
 *  subject common name of a certificate that carries it (the product's CA name for a key published
 *  without a certificate), why the private key is public, and where that is recorded. An entry is added only when its private key has been recovered or obtained and
 *  checked against the public key. `pki.trust.knownCompromisedKeys()` returns a copy. */
var _freeze = require("./guard-intrinsic").freeze;

function _entry(digest, name, reason, sources) {
  return _freeze({ spkiSha256: digest, name: name, reason: reason, sources: _freeze(sources) });
}

var EMUDHRA_SOURCES = [
  "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449",
  "https://blog.cloudflare.com/emudhra-certificate-compromise/",
];
var EMUDHRA_REASON = "the P-384 private key is an integer below 256, which anyone can recover from the public " +
  "key by trying each candidate; eMudhra and Sectigo both issued CA certificates for the key";
function _emudhra(digest, name) { return _entry(digest, name, EMUDHRA_REASON, EMUDHRA_SOURCES); }

var KOMODIA_SOURCES = [
  "https://gist.github.com/Wack0/17c56b77a90073be81d3",
  "https://www.kb.cert.org/vuls/id/529496",
  "https://github.com/hannob/superfishy/tree/afbad9c2635bfd5c4bfa2630c27263f59efecd86/certificates",
];
function _komodia(digest, name, product) {
  return _entry(digest, name, product + " uses the Komodia interception library and installs this root with one " +
    "private key built into the software; the key was published in February 2015", KOMODIA_SOURCES);
}

var ADGUARD_SOURCES = [
  "https://blog.hboeck.de/archives/874-More-TLS-Man-in-the-Middle-failures-Adguard,-Privdog-again-and-ProtocolFilters.dll.html",
  "https://github.com/hannob/superfishy/tree/afbad9c2635bfd5c4bfa2630c27263f59efecd86/certificates",
];
function _adguard(digest, n) {
  return _entry(digest, n === 3 ? "Adguard CA R73" : "Adguard CA", "Adguard ships ten CA private keys in ProtocolFilters.dll and certifies one of " +
    "them as its root on each installation; this is key " + n + " of the ten, and all ten were published in 2015", ADGUARD_SOURCES);
}

var DELL_SOURCES = [
  "https://blog.hboeck.de/archives/876-Superfish-2.0-Dangerous-Certificate-on-Dell-Laptops-breaks-encrypted-HTTPS-Connections.html",
  "https://bugzilla.mozilla.org/show_bug.cgi?id=1227258",
];

var KEYS = _freeze([
  _emudhra("ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105", "EM DV TLS CA - G3B"),
  _emudhra("43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b", "EM OV TLS CA - G3B"),
  _emudhra("e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41", "EM EV TLS CA - G3B"),
  _emudhra("49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f", "EM DV TLS CA - G3C"),
  _emudhra("63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8", "EM OV TLS CA - G3C"),
  _emudhra("5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0", "EM EV TLS CA - G3C"),
  _emudhra("ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6", "EM OV CS CA - G3B"),
  _emudhra("92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30", "EM OV CS CA - G3C"),

  _entry("4bb8f35ba1e126f8dde1b0c420625ed86dce61a7bddadbdea9aba578ff13145e", "Superfish, Inc.",
    "Superfish Visual Discovery, preinstalled on Lenovo consumer laptops, installs this root with one private key " +
    "built into the software; the key and its password were published in February 2015", [
      "https://blog.erratasec.com/2015/02/extracting-superfish-certificate.html",
      "https://www.kb.cert.org/vuls/id/529496",
      "https://github.com/hannob/superfishy/tree/afbad9c2635bfd5c4bfa2630c27263f59efecd86/certificates",
    ]),
  _komodia("2698846608c82e14834b0a99da116097801ae712b1637897c8d305ee1f29b9ce", "KeepMyFamilySecure", "Keep My Family Secure"),
  _komodia("c35169fdc7781d149081f60d6e81f259bd504ce19b53a0370d1dbabecb195437", "Qustodio", "Qustodio for Windows"),
  _komodia("0ab38aff3afae30102ee3713bade6b83c9d27cd78045a9a0372b92031274b48b", "Qustodio CA", "Qustodio for macOS"),
  _komodia("338124a8fdeef46002656293c677a0f73c69b664f847915d20fd6431851df423", "Kurupira.NET", "Kurupira WebFilter"),
  _komodia("eb6aaaedf0a08c2e20a07f5d97125ba66c97f52994f1791462791f4f98af6baa", "AtomPark Software Inc", "StaffCop"),
  _komodia("163b33dd8ee4f658fbbd681cef3abb091d890b39f0fc78289a1d1f7b8d39000f", "EasyTech", "Easy Hide IP Classic"),
  _komodia("aabf9d9003d73799f3c6cc1577ab2b109dbcbf6371eef1e633b9e36bea563db0", "Lavasoft Limited", "Ad-Aware Web Companion"),
  _komodia("5305c2c7f001e9c18269be5d914bc0c767e953d5f8540f2f0db27244c010ff37", "Sendori, Inc", "Sendori and PureLeads"),
  _komodia("6a743e1ff94f445184971182955d919232085a0276e5c6dd9dfff22b367cb7e5", "InfoWeise", "SecureTeen"),
  _komodia("30f397f1523cdd1c1511144ea2c37638ba779b8c49c30d08f682f878bc0c8cbf", "ImpresX OU", "DiscountCow"),
  _komodia("86d8efafc3ede0edaa22a99ea8bd78e0decbae6585da94b438a2af1632e52a83", "Objectify Media Inc", "WebProtect"),
  _komodia("37f8ccfa97ee243ff7ba4e799899bd6524355ee72a0ec9d90ae7cefb81409174", "Covenant Eyes", "Covenant Eyes"),

  _entry("10900ceb22cbcef9e431f6801225df3755f7a75eae0e22f164cae1cbbc81424c", "PrivDog Secure Connection Inspector CA",
    "PrivDog installs this root with the same private key on every installation; the key was published in 2015", [
      "https://blog.hboeck.de/archives/874-More-TLS-Man-in-the-Middle-failures-Adguard,-Privdog-again-and-ProtocolFilters.dll.html",
      "https://github.com/hannob/superfishy/tree/afbad9c2635bfd5c4bfa2630c27263f59efecd86/certificates",
    ]),
  _adguard("f2971080d115de5d766fcf121561a591b20aa053846dc5a45f201080016c69db", 0),
  _adguard("ddeb6f867663dc1e2d298f4abfad1f5e79a5021a2f8930c28e20b45b4bd1ccb1", 1),
  _adguard("acbfc3190dd8588904410d746ba9f1f26727ea722718c3ffd5999f924d50cecf", 2),
  _adguard("ade08a07590eabeac543e87b992d23f11022023d8ecd29c46a16e4082a0e7d96", 3),
  _adguard("bf10a7a8ecacac2f33f65b255eda3f64633557683b604324cfe04ef0cdfe3e5e", 4),
  _adguard("3bf92d4350bab7f85c7eb94c625d7e4101c3750b1f7ea0ccb2107db542486f78", 5),
  _adguard("14b8d90aa31112c29773362edae7b4815f3af4329fa7780d5fc96eba6c78a0e7", 6),
  _adguard("1fd5924ce5b7565b752a6ce8edfe783e04a9bae76fa60da744ca673b0991f528", 7),
  _adguard("1732ba84e3ec722470e3a5166f04825db6e66c6b85ec2648aedbefbef4ed9d81", 8),
  _adguard("cc9ce8160876312f0b510ab58ebd6782675bf595e8d14e1ffe6ce81efa27b3ea", 9),

  _entry("cdee9f3305572a677e1a6c82dc1e02a35b11cae6a684338c9f37fe1ac8daec23", "eDellRoot",
    "Dell installed this root with its private key on Dell computers in 2015; the key was extracted and published", DELL_SOURCES),
  _entry("130ad4e0633521290531b6651f5759b0bc7bc656709ff8f365c2143b0389b6f6", "DSDTestProvider",
    "Dell System Detect installs this root with its private key; the key was extracted and published in 2015", DELL_SOURCES),
  _entry("8ebf425f93b2c7ef59edb0fa840aae95f689503fa2e38a447a0d87975ea0ff75", "bealocalhost.de",
    "the German Federal Bar told lawyers to trust this root in December 2017, and its private key shipped inside the " +
    "beA Client Security software", [
      "https://www.feistyduck.com/newsletter/issue_36_private_keys_in_software",
      "https://dserver.bundestag.de/btd/19/008/1900898.pdf",
    ]),
  _entry("b72c2308eb6129308900bd53995fdb6025aa72c30e43f3527254b3ec87c236db", "DO NOT TRUST - AMI Test PK",
    "the AMI test UEFI Secure Boot platform key (PKfail, CVE-2024-8105); its private key was committed to a public " +
    "repository with its password, and the certificate shipped in production firmware", [
      "https://github.com/binarly-io/Vulnerability-REsearch/blob/main/PKfail/BRLY-2024-005.md",
      "https://www.cve.org/CVERecord?id=CVE-2024-8105",
    ]),
]);

module.exports = _freeze({ KEYS: KEYS });
