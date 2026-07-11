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
 *   (`asn1/indefinite-length`, `x509/not-a-certificate`) -- safe to switch
 *   on and safe to log. Because every failure here is a deterministic
 *   verdict on the bytes in hand (a malformed length, an unknown OID
 *   shape, a truncated certificate), errors are `permanent: true` -- the
 *   same input will never parse on retry.
 *
 * @card
 *   `PkiError` base class + `defineClass` factory + the per-domain error
 *   classes the toolkit throws.
 */

// The frozen shape of every error code: a `domain/reason` string of
// lowercase alphanumerics and dashes.
var CODE_SHAPE = /^[a-z0-9-]+\/[a-z0-9-]+$/;

/**
 * @primitive  pki.errors.PkiError
 * @signature  new PkiError(message, code)
 * @since      0.1.0
 * @status     stable
 * @spec       internal (design: error taxonomy base class)
 *
 * Base class every toolkit error extends. Provides the unified
 * `instanceof` check plus the `{ name, code, isPkiError }` shape.
 * A supplied `code` must be a `domain/reason` string (lowercase
 * alphanumerics and dashes) -- the construction throws a `TypeError`
 * otherwise, which catches an argument-order swap with the
 * `defineClass` subclasses' `(code, message)` convention at the call
 * site instead of shipping prose into a code-switching consumer.
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
    var c = code || "pki/invalid";
    if (typeof c !== "string" || !CODE_SHAPE.test(c)) {
      throw new TypeError(
        "PkiError code must be a domain/reason string, got " + String(c) +
        " (PkiError takes (message, code); defineClass subclasses take (code, message))"
      );
    }
    this.code = c;
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
 * Factory that produces a `PkiError` subclass with the standard shape --
 * eliminating the per-domain boilerplate. The returned constructor takes
 * `(code, message)`, stamps `name`, sets an `is<Name>` flag, and exposes
 * a `.factory` static for the common `var _err = XxxError.factory` shape.
 * The `code` must be a `domain/reason` string (the base-class contract);
 * without `withCause`, a third constructor argument throws a `TypeError`
 * rather than silently discarding a cause the caller meant to thread.
 *
 * @opts
 *   withCause:  boolean,  // default: false -- constructor becomes (code, message, cause)
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
      if (withCause) {
        if (arg3 !== undefined) this.cause = arg3;
      } else if (arg3 !== undefined) {
        throw new TypeError(name + " takes (code, message); to thread a cause, define the class with { withCause: true }");
      }
    }
  };
  Object.defineProperty(GeneratedError, "name", { value: name, configurable: true });
  GeneratedError.factory = function (code, message, arg3) {
    return new GeneratedError(code, message, arg3);
  };
  return GeneratedError;
}

// ---- Per-domain error classes ----

// ConstantsError -- a bad scale argument to C.TIME.* / C.BYTES.* (an
// authoring bug caught at config time).
var ConstantsError = defineClass("ConstantsError");

// Asn1Error -- malformed / non-canonical DER: truncated TLV, indefinite
// length, non-minimal length or integer, leftover trailing bytes, depth
// or size cap exceeded. DER is a canonical encoding, so anything the
// decoder rejects is permanently invalid. withCause threads a raw byte-view
// failure (a detached backing ArrayBuffer) as the cause rather than discarding it.
var Asn1Error = defineClass("Asn1Error", { withCause: true });

// CborError -- malformed / non-deterministic CBOR: a reserved or indefinite
// additional-info value, a stray break, a non-minimal ("preferred") argument,
// a non-shortest or non-canonical-NaN float, an out-of-order or duplicate map
// key, a non-minimal / oversized bignum, bad UTF-8, a wrong-typed tag body,
// leftover trailing bytes, or a depth / size cap exceeded. RFC 8949 core-
// deterministic encoding (sec. 4.2.1) is canonical, so anything the decoder
// rejects is permanently invalid. withCause threads a raw byte-view failure
// (a detached backing ArrayBuffer) as the cause rather than discarding it.
var CborError = defineClass("CborError", { withCause: true });

// OidError -- a malformed object-identifier: fewer than two arcs, a first
// arc outside 0..2, a second arc >= 40 under arcs 0/1, or a non-minimal
// base-128 sub-identifier. withCause threads a raw byte-view failure (a detached
// backing ArrayBuffer at fromDER) as the cause rather than discarding it.
var OidError = defineClass("OidError", { withCause: true });

// PemError -- a malformed PEM envelope: missing / mismatched BEGIN/END
// markers, a bad label, or non-base64 body.
var PemError = defineClass("PemError");

// CertificateError -- a byte sequence that is not a well-formed X.509
// certificate (wrong outer structure, unparseable field, unsupported
// version).
var CertificateError = defineClass("CertificateError", { withCause: true });

// CrlError -- a byte sequence that is not a well-formed X.509 CRL
// (CertificateList / TBSCertList -- RFC 5280 sec. 5).
var CrlError = defineClass("CrlError", { withCause: true });

// SchemaError -- the schema-family orchestrator's own errors (input that matches
// no registered format / does not decode). (code, message) shape like the rest.
var SchemaError = defineClass("SchemaError", { withCause: true });

// CsrError -- a byte sequence that is not a well-formed PKCS#10 CertificationRequest
// (RFC 2986).
var CsrError = defineClass("CsrError", { withCause: true });

// Pkcs8Error -- a byte sequence that is not a well-formed PKCS#8 PrivateKeyInfo /
// OneAsymmetricKey or EncryptedPrivateKeyInfo (RFC 5208 sec. 5, RFC 5958 sec. 2/sec. 3).
var Pkcs8Error = defineClass("Pkcs8Error", { withCause: true });

// CmsError -- a byte sequence that is not a well-formed CMS ContentInfo /
// SignedData (RFC 5652). Carries the underlying leaf fault as `.cause`.
var CmsError = defineClass("CmsError", { withCause: true });

// OcspError -- a byte sequence that is not a well-formed OCSP request or response
// (OCSPRequest / OCSPResponse -- RFC 6960 sec. 4). Carries the leaf fault as `.cause`.
var OcspError = defineClass("OcspError", { withCause: true });

// TspError -- a byte sequence that is not a well-formed RFC 3161 timestamp token,
// TSTInfo, or TimeStampResp. Carries the underlying leaf fault as `.cause`.
var TspError = defineClass("TspError", { withCause: true });

// AttrCertError -- a byte sequence that is not a well-formed X.509 Attribute
// Certificate (AttributeCertificate / AttributeCertificateInfo -- RFC 5755 sec. 4),
// or a recognized-and-deferred legacy AttributeCertificateV1. Carries the
// underlying leaf fault as `.cause`.
var AttrCertError = defineClass("AttrCertError", { withCause: true });

// CrmfError -- a byte sequence that is not a well-formed RFC 4211 CertReqMessages
// / CertReqMsg / CertRequest / CertTemplate. Carries the underlying leaf fault as
// `.cause`.
var CrmfError = defineClass("CrmfError", { withCause: true });

// Pkcs12Error -- a byte sequence that is not a well-formed RFC 7292 PFX
// (AuthenticatedSafe / SafeContents / SafeBag), or a PFX violating a sec. 4
// coherence rule (version, integrity mode, bag dispatch, MacData). Carries
// the underlying leaf fault as `.cause`.
var Pkcs12Error = defineClass("Pkcs12Error", { withCause: true });

// CmpError -- a byte sequence that is not a well-formed RFC 9810 PKIMessage
// (PKIHeader / PKIBody / protection / extraCerts), or one violating a sec. 5
// coherence rule (protection<=>protectionAlg, certConf-hashAlg<=>pvno). Carries
// the underlying leaf fault as `.cause`.
var CmpError = defineClass("CmpError", { withCause: true });

// PathError -- a certification path that fails RFC 5280 sec. 6 validation, or a
// malformed input handed to the validator (an extension value that does not
// decode, an empty path, an unsupported signature algorithm). Carries the
// per-check reason in `.code` (`path/*`) and the underlying leaf fault as
// `.cause`.
var PathError = defineClass("PathError", { withCause: true });

// SmimeError -- a byte sequence that is not a well-formed RFC 5035 ESS
// signing-certificate attribute (SigningCertificate / SigningCertificateV2 /
// ESSCertID(v2) / IssuerSerial) or RFC 8551 SMIMECapabilities, or a CMS
// attribute violating a sec. 2.5 coherence rule (single-AttributeValue, certs
// non-empty, non-canonical DEFAULT hashAlgorithm). Carries the underlying leaf
// fault (e.g. the inner asn1/* decode error) as `.cause`.
var SmimeError = defineClass("SmimeError", { withCause: true });

// CtError -- a byte sequence that is not a well-formed RFC 6962 Certificate
// Transparency SCT list: a malformed inner DER OCTET-STRING wrap, or a TLS
// presentation-language framing violation (a lying vector length, a field read
// past its bound, a truncated element). An SCT whose version this parser does
// not define is NOT an error -- RFC 6962 sec. 3.3 makes unknown versions skippable,
// so they are preserved opaque. Carries the underlying leaf fault (e.g. the
// inner `asn1/*` decode error) as `.cause`.
var CtError = defineClass("CtError", { withCause: true });

// MerkleError -- a malformed input to the RFC 6962 / RFC 9162 Merkle-tree
// proof-verification core: a tree coordinate that is not a non-negative integer
// (or a Number above 2^53 where an exact BigInt is required), a leafIndex
// outside its tree, an inverted consistency window, a hash chunk that is not 32
// bytes, or a proof whose node count does not match the tree geometry. The final
// root comparison is a constant-time boolean (root matched / did not), NOT an
// error -- only a structurally malformed input throws. Carries an underlying
// leaf fault as `.cause`.
var MerkleError = defineClass("MerkleError", { withCause: true });

// CsrattrsError -- a byte sequence that is not a well-formed RFC 8951 sec. 3.5
// CsrAttrs (SEQUENCE OF AttrOrOID), or one violating an RFC 9908 semantic rule
// (a repeated id-ExtensionReq, an extension-request values SET that is not
// exactly one Extensions, a template version other than v1(0), a mixed
// extension-request template). Carries the underlying leaf fault as `.cause`.
var CsrattrsError = defineClass("CsrattrsError", { withCause: true });

// EstError -- an RFC 7030 / 8951 / 9908 Enrollment-over-Secure-Transport
// protocol fault: a payload that fails a per-operation validator (a non-certs-
// only /cacerts response, a serverkeygen recipient-arm mismatch), a transfer /
// multipart framing violation, or an HTTP response the classifier rejects.
// Carries the underlying leaf / delegated fault (e.g. a cms/* or asn1/*) as
// `.cause`.
var EstError = defineClass("EstError", { withCause: true });

// JoseError -- a JOSE (RFC 7515 JWS / RFC 7518 JWA / RFC 7638 thumbprint)
// fault: a non-canonical base64url field, a duplicate JSON member, a
// bounds violation, a header that fails its profile (alg/nonce/url/jwk-kid),
// an unknown or MAC algorithm on the outer profile, a signature of the wrong
// length for its alg, or a verify failure. Carries the underlying leaf fault
// (a webcrypto / asn1 error) as `.cause`.
var JoseError = defineClass("JoseError", { withCause: true });

// AcmeError -- an RFC 8555 / 8737 / 8738 / 9773 ACME message-layer fault: a
// resource object that fails its spec (bad status enum, a missing
// conditionally-required field, an immutable field mutated), an illegal state
// transition, an identifier/token/nonce that fails validation, a CSR whose
// identifiers or key do not match the order, or a renewal window inversion.
// Carries the delegated jose/* or a DER leaf fault as `.cause`.
var AcmeError = defineClass("AcmeError", { withCause: true });

module.exports = {
  PkiError:         PkiError,
  defineClass:      defineClass,
  ConstantsError:   ConstantsError,
  Asn1Error:        Asn1Error,
  CborError:        CborError,
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
  CrmfError:        CrmfError,
  Pkcs12Error:      Pkcs12Error,
  CmpError:         CmpError,
  PathError:        PathError,
  CtError:          CtError,
  MerkleError:      MerkleError,
  SmimeError:       SmimeError,
  CsrattrsError:    CsrattrsError,
  EstError:         EstError,
  JoseError:        JoseError,
  AcmeError:        AcmeError,
};
