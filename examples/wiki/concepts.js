// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// concepts — the wiki's narrative pages. Each /** @concept */ block below
// becomes one page under the Concepts nav group, rendered by
// lib/page-generator with the same prose/section/related machinery the
// primitive pages use. This file is parsed for its comment blocks, never
// executed by the site.

/**
 * @concept fail-closed
 * @title   Fail closed by default
 * @order   10
 * @related pki.errors.PkiError, pki.errors.defineClass, pki.schema.all
 *
 * Every verification path in this toolkit throws on failure. No parse,
 * verify, or validation API returns `false`, `null`, zero, or a partial
 * result in place of a real verdict -- an accept-on-error default is
 * treated as a bug in the library, not an ergonomic for the caller.
 *
 * @section What a failure looks like
 *   Malformed input is a permanent verdict, so it throws a typed error:
 *   every error the toolkit raises extends `PkiError` and carries a
 *   stable, greppable `code` of the form `domain/reason` --
 *   `asn1/trailing-bytes`, `cms/bad-version`, `x509/not-a-certificate`.
 *   A consumer needs a single `err instanceof pki.errors.PkiError` check
 *   and can switch on `err.code` without parsing prose. The full code
 *   inventory is on the Error catalog reference page, harvested from the
 *   source at boot.
 *
 * @section Why throwing beats returning false
 *   A boolean verify result composes badly: one forgotten `if` and a
 *   failed signature check becomes a successful code path. A thrown,
 *   typed error inverts the failure mode -- ignoring it stops the
 *   program instead of accepting the forgery. The same posture applies
 *   inside the library: internal helpers never swallow a verification
 *   error into a default value on the way up.
 *
 * @section Bounded before it walks
 *   Fail-closed includes resource exhaustion. The DER decoder enforces
 *   size and depth caps before it walks a byte, so a hostile input can
 *   fail fast with a typed error instead of exhausting memory or the
 *   stack. Parsing hostile bytes may only succeed or throw a
 *   `PkiError` -- that contract is fuzzed continuously.
 */

/**
 * @concept pqc-first
 * @title   Post-quantum first
 * @order   20
 * @related pki.webcrypto, pki.oid
 *
 * The NIST post-quantum algorithms -- ML-DSA (FIPS 204), ML-KEM
 * (FIPS 203), and SLH-DSA (FIPS 205) -- are first-class registry entries
 * in this toolkit, wired through the same paths as RSA, ECDSA, and
 * EdDSA. They are not an add-on module or an experimental flag.
 *
 * @section The registry is the design
 *   Algorithms resolve through an OID-keyed registry: OID to parameters
 *   to key import to sign/verify. No format module hardcodes an
 *   algorithm switch, so adding an algorithm is a data row plus a
 *   signer -- not a special case threaded through every parser. That is
 *   what keeps classical and post-quantum algorithms structurally equal:
 *   the certificate, CMS, and timestamping paths do not know which
 *   family they are verifying.
 *
 * @section Native crypto only
 *   The cryptography runs on Node's built-in `node:crypto` -- classical
 *   and FIPS post-quantum both. The toolkit ships zero npm runtime
 *   dependencies and vendors no cryptographic code, so the crypto you
 *   run is the crypto your Node runtime ships and patches.
 *
 * @section No classical-only defaults
 *   Where a post-quantum or hybrid option exists, the toolkit does not
 *   default to a classical-only choice. Operators migrating ahead of the
 *   quantum transition should not have to fight their PKI library's
 *   defaults to get there.
 */

/**
 * @concept strict-der
 * @title   Strict DER, byte for byte
 * @order   30
 * @related pki.asn1.decode, pki.asn1.encode, pki.schema.all
 *
 * The toolkit owns its ASN.1 codec, and the codec is strict: decode
 * accepts canonical DER and nothing else, encode emits canonical DER and
 * nothing else. Every non-DER shape -- indefinite lengths, non-minimal
 * length or integer encodings, constructed strings, trailing bytes after
 * the outermost value -- is rejected with a typed error naming the
 * reason.
 *
 * @section Why strictness is a security property
 *   Most X.509 and CMS parser vulnerabilities are lenience bugs: two
 *   implementations accept the same bytes but disagree on what they
 *   mean, and the gap becomes a signature bypass or an identity
 *   confusion. A strict decoder collapses that ambiguity -- there is
 *   exactly one byte sequence for a given value, so what was signed is
 *   what was parsed.
 *
 * @section Round-trip identity
 *   A format parser here round-trips a valid input to identical bytes,
 *   and the byte ranges an external verifier hashes -- a certificate's
 *   `tbs`, a CMS `eContent` -- are surfaced raw from the input, never
 *   re-serialized. Signature verification therefore runs over the bytes
 *   that were actually presented, not over a best-effort re-encoding.
 *
 * @section One structure, both directions
 *   Each ASN.1 structure is declared once, and that single declaration
 *   drives both encode and decode. Context-tag handling (EXPLICIT versus
 *   IMPLICIT) cannot drift between the two directions, because there are
 *   no two implementations to drift.
 */

module.exports = {};
