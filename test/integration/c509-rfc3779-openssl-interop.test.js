// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Integration -- RFC 3779 IP address / AS number extensions through the C509 compact value
 * codec, cross-checked against OpenSSL in both directions.
 *
 * OpenSSL is the independent oracle, and for these extensions it is an unusually strong one:
 * it both MINTS the structures (sbgp-ipAddrBlock / sbgp-autonomousSysNum via -extfile) and
 * ENFORCES their canonical form (`openssl verify` reports X509v3_addr_is_canonical /
 * X509v3_asid_is_canonical failures as error 41 X509_V_ERR_INVALID_EXTENSION). Note that only
 * `verify` enforces -- `x509 -text` prints a non-canonical list happily -- so acceptance and
 * rejection are both read off `verify`, never off the printer.
 *
 * This file establishes:
 *  (a) an OpenSSL-minted certificate carrying both extensions compacts to C509 extension
 *      integers 32 / 33 and reconstructs the source DER byte-for-byte, across the address forms
 *      the draft distinguishes -- prefix, range, the byte-string form an address wider than
 *      8 octets forces, a SAFI-qualified family, and inherit;
 *  (b) the reconstruction is a certificate OpenSSL still verifies, so the issuer signature
 *      survives the round trip;
 *  (c) the negative direction -- a certificate whose address list violates the RFC 3779
 *      sec. 2.2.3.6 canonical order is rejected by `openssl verify`, the codec declines to
 *      compact it (it falls back to the unwrapped-OID byte-string form), and the reconstructed
 *      bytes are still rejected. A non-conforming certificate is never repaired into a
 *      conforming one, which would mean the signed bytes had changed.
 *
 * Runs under scripts/test-integration.js; the service-check gate confirms `openssl` first.
 */

var ctx = require("./_interop-ctx");
var pki = ctx.pki;
var check = ctx.check;
var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var b = pki.asn1.build;

// The unwrapped-OID fallback keys an extension by the CONTENT octets of its OID, so the expected
// key is derived from the registry rather than written out -- a registry edit moves both together.
function oidContent(name) {
  return pki.asn1.decode(b.oid(pki.oid.byName(name))).content.toString("hex");
}

// The C509 extensions array is a flat (identifier, value) pair list: a signed integer identifier
// for a registered extension (negative = critical) or a byte string carrying the unwrapped OID
// when no compact value form applies.
function c509Exts(c509) {
  var kids = pki.cbor.decode(c509).children[9].children || [];
  var out = [];
  for (var i = 0; i + 1 < kids.length; i += 2) {
    var k = kids[i];
    out.push({
      id:    k.majorType <= 1 ? Number(pki.cbor.read.int(k)) : null,
      oid:   k.majorType === 2 ? k.content.toString("hex") : null,
      value: kids[i + 1],
    });
  }
  return out;
}
function byId(exts, id) {
  var hit = exts.filter(function (e) { return e.id === id; });
  return hit.length === 1 ? hit[0].value : null;
}
function byOid(exts, hex) {
  var hit = exts.filter(function (e) { return e.oid === hex; });
  return hit.length === 1 ? hit[0].value : null;
}
// A CBOR array's child major types, as a comma-joined string, so a value's shape is asserted as a
// whole rather than by poking individual indices.
function shape(node) {
  if (!node || node.majorType !== 4 || !node.children) return null;
  return node.children.map(function (c) { return c.majorType; }).join(",");
}

function run() {
  // An OpenSSL built with OPENSSL_NO_RFC3779 knows neither the OIDs nor the extension methods,
  // and cannot act as the oracle at all.
  var objects = ctx.runOpenssl(["list", "-objects"], { allowNonZero: true });
  if (objects.code !== 0 || !/sbgp-ipAddrBlock/.test(objects.stdout)) {
    ctx.skip("openssl on PATH does not know the RFC 3779 object identifiers (built with OPENSSL_NO_RFC3779?) -- RFC 3779 interop not cross-checked");
    return;
  }

  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "pkijs-rfc3779-"));
  try { body(dir); }
  finally { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ } }
}

function body(dir) {
  function f(n) { return path.join(dir, n); }
  var caPem = f("ca.pem");

  // The CA carries a superset of every resource an end entity below claims: RFC 3779 sec. 2.3
  // path validation is unconditional in `openssl verify`, so a leaf whose resources are not
  // nested under its issuer's fails with error 46 and would mask the canonical-form verdict
  // this file is actually reading.
  var world = mintWorld(dir);
  if (world.error) {
    ctx.skip("openssl on PATH cannot mint RFC 3779 certificates (" + world.error + ") -- RFC 3779 interop not cross-checked");
    return;
  }

  // `openssl verify` takes the certificate as a positional PEM argument on this surface; it has
  // no -in / -inform of its own, so a DER reconstruction is converted before it is judged.
  function verifyPem(p) { return ctx.runOpenssl(["verify", "-CAfile", caPem, p], { allowNonZero: true }); }
  function verifyDer(der) {
    return ctx.withTmp(der, "recon.der", function (dp) {
      var pemPath = dp + ".pem";
      try {
        var conv = ctx.runOpenssl(["x509", "-in", dp, "-inform", "DER", "-out", pemPath], { allowNonZero: true });
        if (conv.code !== 0) return { code: conv.code, stdout: "", stderr: conv.stderr };
        return verifyPem(pemPath);
      } finally { try { fs.unlinkSync(pemPath); } catch (_e) { /* best-effort */ } }
    });
  }
  function accepted(r) { return r.code === 0 && /: OK/.test(r.stdout + r.stderr); }
  function rejectedInvalidExtension(r) { return r.code !== 0 && /error 41/.test(r.stdout + r.stderr); }
  // Every certificate here is ECDSA P-256 over SHA-256, which the type-3 covered set carries; the
  // issuer curve is supplied because a self-issued chain does not name it in the certificate.
  function toC509(der) { return pki.schema.c509.encode(der, { issuerCurve: "P-256" }); }
  function reconOf(c509) { return pki.schema.c509.parse(c509).reconstructedDer; }

  var IP_OID = oidContent("ipAddrBlocks");
  var AS_OID = oidContent("autonomousSysIds");

  // ---- (a)+(b) the canonical certificate: both extensions, two address families, prefix + range
  var okC509 = toC509(world.ok);
  var okExts = c509Exts(okC509);
  var okIp = byId(okExts, -32), okAs = byId(okExts, -33);
  check("openssl verify accepts the OpenSSL-minted RFC 3779 certificate", accepted(verifyPem(world.okPem)));
  check("sbgp-ipAddrBlock rides C509 extension integer 32, critical (-32), as a compact CBOR array",
    okIp !== null && okIp.majorType === 4);
  // IPAddressFamily is a parenthesized CDDL group, so it splices FLAT: one array of
  // AFI, SAFI, choice per family -- not an array of three-element arrays.
  check("the IPAddrBlocks array splices IPAddressFamily flat (AFI, SAFI, choice per family)",
    okIp !== null && okIp.children.length === 6 && okIp.children.length % 3 === 0 && shape(okIp) === "0,7,4,0,7,4");
  check("sbgp-autonomousSysNum rides C509 extension integer 33, critical (-33), as a compact CBOR array",
    okAs !== null && okAs.majorType === 4);
  check("the ASIdentifiers array carries a single ASId and an ASRange pair", shape(okAs) === "0,4");
  check("the compact C509 encoding is smaller than the OpenSSL-minted DER", okC509.length < world.ok.length);
  var okRecon = reconOf(okC509);
  check("parse reconstructs the OpenSSL-minted RFC 3779 certificate byte-for-byte", okRecon.equals(world.ok));
  check("openssl verify accepts the reconstructed certificate -- the issuer signature survives the round trip",
    accepted(verifyDer(okRecon)));

  // ---- the byte-string address form: an IPv6 /64 is 9 octets of unusedBits||value, past the
  // 8-octet integer-form ceiling, so the WHOLE family SHALL use the byte-string form.
  var b64Exts = c509Exts(toC509(world.bytes64));
  var b64Ip = byId(b64Exts, -32);
  check("an IPv6 /64 family exceeds the 8-octet integer-form ceiling and rides the byte-string address form",
    b64Ip !== null && shape(b64Ip) === "0,7,4" && shape(b64Ip.children[2]) === "2");
  var b64Recon = reconOf(toC509(world.bytes64));
  check("the byte-string-form certificate reconstructs byte-for-byte", b64Recon.equals(world.bytes64));
  check("openssl verify accepts the reconstructed byte-string-form certificate", accepted(verifyDer(b64Recon)));

  // ---- a SAFI-qualified family: addressFamily is OCTET STRING (SIZE (2..3)), the third octet
  // being the SAFI, which occupies the CBOR slot that is null when absent.
  var safiIp = byId(c509Exts(toC509(world.safi)), -32);
  check("a SAFI-qualified address family carries the SAFI octet in the CBOR uint slot, not null",
    safiIp !== null && shape(safiIp) === "0,0,4");
  var safiRecon = reconOf(toC509(world.safi));
  check("the SAFI-qualified certificate reconstructs byte-for-byte", safiRecon.equals(world.safi));
  check("openssl verify accepts the reconstructed SAFI-qualified certificate", accepted(verifyDer(safiRecon)));

  // ---- inherit: a null address choice per family, and a null ASIdentifiers value outright.
  var inhExts = c509Exts(toC509(world.inherit));
  var inhIp = byId(inhExts, -32), inhAs = byId(inhExts, -33);
  check("an inherit IP family carries a null address choice in each family triple",
    inhIp !== null && shape(inhIp) === "0,7,7,0,7,7");
  check("an inherit ASIdentifiers is the CBOR null value outright", inhAs !== null && inhAs.majorType === 7);
  var inhRecon = reconOf(toC509(world.inherit));
  check("the inherit certificate reconstructs byte-for-byte", inhRecon.equals(world.inherit));
  check("openssl verify accepts the reconstructed inherit certificate", accepted(verifyDer(inhRecon)));

  // ---- criticality is the sign of the extension identifier; RFC 3779 says SHOULD be critical, so
  // the positive arm is the one that needs pinning.
  var ncIp = byId(c509Exts(toC509(world.nonCritical)), 32);
  check("a non-critical sbgp-ipAddrBlock rides the POSITIVE extension integer 32", ncIp !== null && ncIp.majorType === 4);
  var ncRecon = reconOf(toC509(world.nonCritical));
  check("the non-critical certificate reconstructs byte-for-byte and openssl verify accepts it",
    ncRecon.equals(world.nonCritical) && accepted(verifyDer(ncRecon)));

  // ---- RFC 8360 v2: encoded exactly like the v1 twins, so the same two codecs serve ints 34/35.
  var v2Exts = c509Exts(toC509(world.v2));
  var v2Ip = byId(v2Exts, 34), v2As = byId(v2Exts, 35);
  check("the RFC 8360 v2 extensions route through the same codecs as extension integers 34 and 35",
    v2Ip !== null && shape(v2Ip) === "0,7,4" && v2As !== null && shape(v2As) === "0");
  var v2Recon = reconOf(toC509(world.v2));
  check("the v2 certificate reconstructs byte-for-byte", v2Recon.equals(world.v2));
  check("openssl verify accepts the reconstructed v2 certificate", accepted(verifyDer(v2Recon)));
  ctx.skip("openssl has an object identifier but no extension method for the RFC 8360 v2 pair, so a CRITICAL v2 extension is reported unhandled (error 34) -- critical-v2 acceptance is not cross-checked");

  // ---- (c) the negative direction: the RFC's own sec. 2.2.3.6 example, in the wrong order.
  // 10.64.0.0/16 sorts BEFORE 10.32.0.0/12 by DER content bytes and by the compact integer, and
  // AFTER it by the RFC's `<lowest address> | <prefix length>` key -- so this vector fails
  // whenever the ordering gate is computed on the wrong key.
  var badVerify = verifyPem(world.ipDescendingPem);
  check("openssl verify rejects an address list that violates the RFC 3779 sec. 2.2.3.6 canonical order (error 41)",
    rejectedInvalidExtension(badVerify));
  var badExts = c509Exts(toC509(world.ipDescending));
  var badFallback = byOid(badExts, IP_OID);
  check("the codec declines to compact the non-canonically ordered address list and falls back to the unwrapped-OID form",
    badFallback !== null && byId(badExts, -32) === null && byId(badExts, 32) === null);
  check("the critical unwrapped-OID fallback wraps the extension DER in a one-element CBOR array",
    badFallback !== null && badFallback.majorType === 4 && shape(badFallback) === "2");
  var badRecon = reconOf(toC509(world.ipDescending));
  check("the unwrapped-OID fallback preserves the certificate bytes exactly", badRecon.equals(world.ipDescending));
  check("openssl verify still rejects the reconstructed certificate -- the ordering defect is preserved, not repaired",
    rejectedInvalidExtension(verifyDer(badRecon)));

  // ---- a descending ASId list is likewise non-canonical to OpenSSL. Whether the codec compacts
  // such a list or falls back to the unwrapped-OID form, the load-bearing invariant is the same:
  // the reconstruction is byte-identical, so the defect survives and an independent verifier
  // still refuses the certificate. A round trip that turned it into an accepted certificate
  // would mean the signed bytes had been rewritten.
  check("openssl verify rejects a descending ASId list (error 41)", rejectedInvalidExtension(verifyPem(world.asDescendingPem)));
  var asDescRecon = reconOf(toC509(world.asDescending));
  check("the descending ASId certificate reconstructs byte-for-byte", asDescRecon.equals(world.asDescending));
  check("openssl verify still rejects the reconstructed descending ASId certificate",
    rejectedInvalidExtension(verifyDer(asDescRecon)));

  // ---- rdi has no compact form at all, so the whole extension rides the unwrapped-OID form.
  var rdiExts = c509Exts(toC509(world.asRdi));
  check("an ASIdentifiers carrying rdi has no compact form and falls back to the unwrapped-OID form",
    byOid(rdiExts, AS_OID) !== null && byId(rdiExts, -33) === null && byId(rdiExts, 33) === null);
  check("the rdi certificate reconstructs byte-for-byte", reconOf(toC509(world.asRdi)).equals(world.asRdi));
}

// Mint the whole certificate world with openssl: a CA holding a superset of resources, then one
// end-entity certificate per address form under test. Happy-path extensions go through -extfile,
// whose config parser canonicalizes (it merges adjacent ranges and re-sorts); the adversarial
// vectors are injected as raw DER, which is passed through untouched. Returns { error } naming
// the failed step when this build cannot mint them, which the caller surfaces as a SKIP.
function mintWorld(dir) {
  function f(n) { return path.join(dir, n); }
  try {
    fs.writeFileSync(f("ca.cnf"),
      "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=RFC3779 Interop CA\n" +
      "[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n" +
      "sbgp-ipAddrBlock=critical,@ipca\nsbgp-autonomousSysNum=critical,@asca\n" +
      "[ipca]\nIPv4.0=10.0.0.0/8\nIPv4-SAFI.0=1:10.0.0.0/8\nIPv6.0=2001:db8::/32\n" +
      "[asca]\nAS.0=1-65535\n");
    ctx.runOpenssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", f("ca.key")]);
    ctx.runOpenssl(["req", "-x509", "-new", "-key", f("ca.key"), "-sha256", "-days", "400",
      "-config", f("ca.cnf"), "-extensions", "v3_ca", "-out", f("ca.pem")]);
    ctx.runOpenssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", f("ee.key")]);
    ctx.runOpenssl(["req", "-new", "-key", f("ee.key"), "-sha256", "-subj", "/CN=RFC3779 Interop EE", "-out", f("ee.csr")]);

    function issue(name, extText) {
      fs.writeFileSync(f(name + ".ext"), extText);
      ctx.runOpenssl(["x509", "-req", "-in", f("ee.csr"), "-CA", f("ca.pem"), "-CAkey", f("ca.key"),
        "-CAcreateserial", "-sha256", "-days", "200", "-extfile", f(name + ".ext"), "-out", f(name + ".pem")]);
      return f(name + ".pem");
    }
    function derOf(pemPath) {
      var outPath = pemPath + ".der";
      ctx.runOpenssl(["x509", "-in", pemPath, "-outform", "DER", "-out", outPath]);
      return fs.readFileSync(outPath);
    }
    // Raw DER for the vectors the config parser would canonicalize away.
    function ipFamily(afi, addrs) {
      return b.sequence([b.sequence([b.octetString(Buffer.from(afi)), b.sequence(addrs)])]);
    }
    var descendingIp = ipFamily([0x00, 0x01], [
      b.bitString(Buffer.from([0x0a, 0x40]), 0),   // 10.64.0.0/16
      b.bitString(Buffer.from([0x0a, 0x20]), 4),   // 10.32.0.0/12 -- lower address, so it must come first
    ]);
    var descendingAs = b.sequence([b.explicit(0, b.sequence([b.integer(64700n), b.integer(64500n)]))]);
    var v2Ip = ipFamily([0x00, 0x01], [b.bitString(Buffer.from([0x0a, 0x05]), 0)]);
    var v2As = b.sequence([b.explicit(0, b.sequence([b.integer(64500n)]))]);
    var V2_IP_OID = pki.oid.byName("ipAddrBlocksV2"), V2_AS_OID = pki.oid.byName("autonomousSysIdsV2");

    var okPem = issue("ok",
      "sbgp-ipAddrBlock=critical,@i\nsbgp-autonomousSysNum=critical,@a\n" +
      "[i]\nIPv4.0=10.1.0.0/16\nIPv6.0=2001:db8:1::/48\n" +
      "[a]\nAS.0=64500\nAS.1=64600-64700\n");
    var bytes64Pem = issue("bytes64", "sbgp-ipAddrBlock=critical,@i\n[i]\nIPv6.0=2001:db8::/64\n");
    var safiPem = issue("safi", "sbgp-ipAddrBlock=critical,@i\n[i]\nIPv4-SAFI.0=1:10.51.100.0/24\n");
    var inheritPem = issue("inherit",
      "sbgp-ipAddrBlock=critical,@i\nsbgp-autonomousSysNum=critical,@a\n" +
      "[i]\nIPv4.0=inherit\nIPv6.0=inherit\n[a]\nAS.0=inherit\n");
    var ncPem = issue("nc", "sbgp-ipAddrBlock=@i\n[i]\nIPv4.0=10.7.0.0/16\n");
    // The v2 pair is injected non-critical: openssl has no extension method for these OIDs, so a
    // critical instance would be refused as an unhandled critical extension before the RFC 3779
    // canonical-form and nesting checks this file reads are ever reached.
    var v2Pem = issue("v2",
      V2_IP_OID + "=DER:" + v2Ip.toString("hex") + "\n" + V2_AS_OID + "=DER:" + v2As.toString("hex") + "\n");
    var ipDescPem = issue("ipdesc", "sbgp-ipAddrBlock=critical,DER:" + descendingIp.toString("hex") + "\n");
    var asDescPem = issue("asdesc", "sbgp-autonomousSysNum=critical,DER:" + descendingAs.toString("hex") + "\n");
    var rdiPem = issue("rdi", "sbgp-autonomousSysNum=critical,@a\n[a]\nAS.0=64500\nRDI.0=7-9\n");

    return {
      okPem: okPem, ok: derOf(okPem),
      bytes64: derOf(bytes64Pem),
      safi: derOf(safiPem),
      inherit: derOf(inheritPem),
      nonCritical: derOf(ncPem),
      v2: derOf(v2Pem),
      ipDescendingPem: ipDescPem, ipDescending: derOf(ipDescPem),
      asDescendingPem: asDescPem, asDescending: derOf(asDescPem),
      asRdi: derOf(rdiPem),
    };
  } catch (e) {
    return { error: String((e && e.message) || e).split("\n")[0] };
  }
}

Promise.resolve().then(run).then(
  function () { console.log("CHECKS " + require("../helpers").getChecks()); console.log("SKIPS " + require("../helpers").getSkips()); },
  function (e) { console.error(require("../helpers").formatErr(e)); process.exit(1); }
);
