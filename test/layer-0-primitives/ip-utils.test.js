// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 -- lib/ip-utils (@internal): strict textual IP-literal validation shared by the
 * consumers that must classify a string as an IP (pki.lint's commonName-in-SAN check). An
 * engine primitive with no operator namespace, so it is pinned directly here. Cross-checked
 * for parity against node:net's isIP across the vector set (the module exists so the toolkit
 * needs no networking module of its own, not to diverge from its classification).
 */

var net = require("net");
var ip = require("../../lib/ip-utils");
var helpers = require("../helpers");
var check = helpers.check;

function run() {
  // --- isIPv4: strict per-octet 0-255 ---
  check("isIPv4 accepts a dotted quad", ip.isIPv4("203.0.113.42") === true);
  check("isIPv4 accepts 0.0.0.0 and 255.255.255.255", ip.isIPv4("0.0.0.0") && ip.isIPv4("255.255.255.255"));
  check("isIPv4 rejects an octet over 255", ip.isIPv4("256.0.0.1") === false);
  check("isIPv4 rejects 999.999.999.999", ip.isIPv4("999.999.999.999") === false);
  check("isIPv4 rejects a three-octet address", ip.isIPv4("1.2.3") === false);
  check("isIPv4 rejects a five-octet address", ip.isIPv4("1.2.3.4.5") === false);
  check("isIPv4 rejects a non-string", ip.isIPv4(1234) === false);

  // --- expandIpv6Hex: RFC 4291 forms + null on malformed ---
  check("expandIpv6Hex expands ::1", ip.expandIpv6Hex("::1") === "00000000000000000000000000000001");
  check("expandIpv6Hex expands a full form", ip.expandIpv6Hex("2001:db8:0:0:0:0:0:1") === "20010db8000000000000000000000001");
  check("expandIpv6Hex expands a compressed form", ip.expandIpv6Hex("2001:db8::1") === "20010db8000000000000000000000001");
  check("expandIpv6Hex expands an IPv4-mapped dual-stack tail", ip.expandIpv6Hex("::ffff:192.0.2.1") === "00000000000000000000ffffc0000201");
  check("expandIpv6Hex rejects a non-colon string", ip.expandIpv6Hex("192.0.2.1") === null);
  check("expandIpv6Hex rejects a non-string", ip.expandIpv6Hex(42) === null);
  check("expandIpv6Hex rejects a non-hex group", ip.expandIpv6Hex("gggg::1") === null);
  check("expandIpv6Hex rejects an over-length group", ip.expandIpv6Hex("12345::1") === null);
  check("expandIpv6Hex rejects more than one ::", ip.expandIpv6Hex("1::2::3") === null);
  check("expandIpv6Hex rejects too many groups", ip.expandIpv6Hex("1:2:3:4:5:6:7:8:9") === null);
  check("expandIpv6Hex rejects a short non-compressed form", ip.expandIpv6Hex("1:2:3") === null);
  check("expandIpv6Hex rejects an over-length textual form", ip.expandIpv6Hex("11111:2222:3333:4444:5555:6666:7777:8888:9999") === null);
  check("expandIpv6Hex rejects an out-of-range mapped quad", ip.expandIpv6Hex("::ffff:999.0.0.1") === null);
  check("expandIpv6Hex rejects an empty group run beyond a single ::", ip.expandIpv6Hex(":::1") === null);
  check("expandIpv6Hex expands a trailing-:: address", ip.expandIpv6Hex("fe80::") === "fe800000000000000000000000000000");
  check("expandIpv6Hex expands :: (all zeros)", ip.expandIpv6Hex("::") === "00000000000000000000000000000000");
  check("expandIpv6Hex rejects too many groups with a ::", ip.expandIpv6Hex("1:2:3:4:5:6:7:8::9") === null);
  // A "::" that compresses ZERO groups is invalid (RFC 4291 sec. 2.2) -- net.isIP rejects it.
  check("expandIpv6Hex rejects a :: compressing zero groups", ip.expandIpv6Hex("1:2:3:4:5:6:7::8") === null);
  check("expandIpv6Hex accepts a :: compressing one group", ip.expandIpv6Hex("1:2:3:4:5:6::8") !== null);

  // --- isIpLiteral: IPv4 OR IPv6 ---
  check("isIpLiteral accepts IPv4", ip.isIpLiteral("192.0.2.1") === true);
  check("isIpLiteral accepts IPv6", ip.isIpLiteral("2001:db8::1") === true);
  check("isIpLiteral accepts a dual-stack literal", ip.isIpLiteral("::ffff:192.0.2.1") === true);
  check("isIpLiteral rejects a hostname", ip.isIpLiteral("example.com") === false);
  check("isIpLiteral rejects a colon non-address", ip.isIpLiteral("api:443") === false);

  // --- parity with node:net.isIP across the vector set ---
  var vectors = ["192.0.2.1", "999.999.999.999", "256.1.1.1", "api:443", "::1", "2001:db8::1",
    "fe80::1", "::ffff:192.0.2.1", "example.com", "1.2.3", "1.2.3.4.5", "gggg::1", ":::1",
    "12345::1", "255.255.255.255", "::ffff:999.0.0.1"];
  var mism = 0;
  vectors.forEach(function (v) { if ((net.isIP(v) !== 0) !== ip.isIpLiteral(v)) mism++; });
  check("isIpLiteral matches node:net.isIP across the vector set", mism === 0);

  console.log("CHECKS " + helpers.getChecks());
}

module.exports = { run: run };

if (require.main === module) run();
