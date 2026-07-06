// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.errors
 * @nav        Core
 * @title      Errors
 * @order      20
 * @slug       errors
 *
 * @intro
 *   Error taxonomy for the toolkit. Every error the library throws
 *   extends `PkiError`, so a consumer needs a single
 *   `err instanceof pki.errors.PkiError` check instead of sniffing per-
 *   module boolean flags, and every error carries a stable shape:
 *   `{ name, code, message, permanent, isPkiError: true }`.
 *
 *   `code` is a stable, greppable `domain/reason` string
 *   (`asn1/indefinite-length`, `x509/not-a-certificate`) — safe to switch
 *   on and safe to log. Because every failure here is a deterministic
 *   verdict on the bytes in hand (a malformed length, an unknown OID
 *   shape, a truncated certificate), errors are `permanent: true` — the
 *   same input will never parse on retry.
 *
 * @card
 *   `PkiError` base class + `defineClass` factory + the per-domain error
 *   classes the toolkit throws.
 */

/**
 * @primitive  pki.errors.PkiError
 * @signature  new PkiError(message, code)
 * @since      0.1.0
 * @status     stable
 * @spec       internal (design: error taxonomy base class)
 *
 * Base class every toolkit error extends. Provides the unified
 * `instanceof` check plus the `{ name, code, isPkiError }` shape.
 *
 * @example
 *   try { pki.asn1.decode(bytes); }
 *   catch (e) {
 *     if (e instanceof pki.errors.PkiError) console.error(e.code);
 *   }
 */
class PkiError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "PkiError";
    this.code = code || "pki/invalid";
    this.isPkiError = true;
    this.permanent = true;
  }
}

/**
 * @primitive  pki.errors.defineClass
 * @signature  pki.errors.defineClass(name, opts?) -> constructor
 * @since      0.1.0
 * @status     stable
 * @spec       internal (design: error-class factory)
 *
 * Factory that produces a `PkiError` subclass with the standard shape —
 * eliminating the per-domain boilerplate. The returned constructor takes
 * `(code, message)`, stamps `name`, sets an `is<Name>` flag, and exposes
 * a `.factory` static for the common `var _err = XxxError.factory` shape.
 *
 * @opts
 *   withCause:  boolean,  // default: false — constructor becomes (code, message, cause)
 *
 * @example
 *   var MyError = pki.errors.defineClass("MyError");
 *   throw new MyError("my/bad-input", "explanation");
 */
function defineClass(name, opts) {
  if (typeof name !== "string" || name.length === 0) {
    throw new TypeError("defineClass: name must be a non-empty string");
  }
  opts = opts || {};
  var withCause = !!opts.withCause;
  var flagKey = "is" + name;

  var GeneratedError = class extends PkiError {
    constructor(code, message, arg3) {
      super(message, code);
      this.name = name;
      this[flagKey] = true;
      if (withCause && arg3 !== undefined) this.cause = arg3;
    }
  };
  Object.defineProperty(GeneratedError, "name", { value: name, configurable: true });
  GeneratedError.factory = function (code, message, arg3) {
    return new GeneratedError(code, message, arg3);
  };
  return GeneratedError;
}

// ---- Per-domain error classes ----

// ConstantsError — a bad scale argument to C.TIME.* / C.BYTES.* (an
// authoring bug caught at config time).
var ConstantsError = defineClass("ConstantsError");

// Asn1Error — malformed / non-canonical DER: truncated TLV, indefinite
// length, non-minimal length or integer, leftover trailing bytes, depth
// or size cap exceeded. DER is a canonical encoding, so anything the
// decoder rejects is permanently invalid.
var Asn1Error = defineClass("Asn1Error");

// OidError — a malformed object-identifier: fewer than two arcs, a first
// arc outside 0..2, a second arc >= 40 under arcs 0/1, or a non-minimal
// base-128 sub-identifier.
var OidError = defineClass("OidError");

// PemError — a malformed PEM envelope: missing / mismatched BEGIN/END
// markers, a bad label, or non-base64 body.
var PemError = defineClass("PemError");

// CertificateError — a byte sequence that is not a well-formed X.509
// certificate (wrong outer structure, unparseable field, unsupported
// version).
var CertificateError = defineClass("CertificateError", { withCause: true });

// CrlError — a byte sequence that is not a well-formed X.509 CRL
// (CertificateList / TBSCertList — RFC 5280 §5).
var CrlError = defineClass("CrlError", { withCause: true });

// SchemaError — the schema-family orchestrator's own errors (input that matches
// no registered format / does not decode). (code, message) shape like the rest.
var SchemaError = defineClass("SchemaError", { withCause: true });

// CsrError — a byte sequence that is not a well-formed PKCS#10 CertificationRequest
// (RFC 2986).
var CsrError = defineClass("CsrError", { withCause: true });

// Pkcs8Error — a byte sequence that is not a well-formed PKCS#8 PrivateKeyInfo /
// OneAsymmetricKey or EncryptedPrivateKeyInfo (RFC 5208 §5, RFC 5958 §2/§3).
var Pkcs8Error = defineClass("Pkcs8Error", { withCause: true });

// CmsError — a byte sequence that is not a well-formed CMS ContentInfo /
// SignedData (RFC 5652). Carries the underlying leaf fault as `.cause`.
var CmsError = defineClass("CmsError", { withCause: true });

// OcspError — a byte sequence that is not a well-formed OCSP request or response
// (OCSPRequest / OCSPResponse — RFC 6960 §4). Carries the leaf fault as `.cause`.
var OcspError = defineClass("OcspError", { withCause: true });

// TspError — a byte sequence that is not a well-formed RFC 3161 timestamp token,
// TSTInfo, or TimeStampResp. Carries the underlying leaf fault as `.cause`.
var TspError = defineClass("TspError", { withCause: true });

// AttrCertError — a byte sequence that is not a well-formed X.509 Attribute
// Certificate (AttributeCertificate / AttributeCertificateInfo — RFC 5755 §4),
// or a recognized-and-deferred legacy AttributeCertificateV1. Carries the
// underlying leaf fault as `.cause`.
var AttrCertError = defineClass("AttrCertError", { withCause: true });

module.exports = {
  PkiError:         PkiError,
  defineClass:      defineClass,
  ConstantsError:   ConstantsError,
  Asn1Error:        Asn1Error,
  OidError:         OidError,
  PemError:         PemError,
  CertificateError: CertificateError,
  CrlError:         CrlError,
  SchemaError:      SchemaError,
  CsrError:         CsrError,
  Pkcs8Error:       Pkcs8Error,
  CmsError:         CmsError,
  OcspError:        OcspError,
  TspError:         TspError,
  AttrCertError:    AttrCertError,
};
