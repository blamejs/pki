// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     pki.errors
 * @nav        Core
 * @title      Errors
 * @fullname   Error classes and the stable domain/reason codes they carry
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
 *   (`asn1/indefinite-length`, `x509/not-a-certificate`): safe to switch
 *   on and safe to log. Because every failure here is a deterministic
 *   verdict on the bytes in hand (a malformed length, an unknown OID
 *   shape, a truncated certificate), errors are `permanent: true`. The
 *   same input will never parse on retry.
 *
 * @card
 *   `PkiError` base class + `defineClass` factory + the per-domain error
 *   classes the toolkit throws.
 */

var intrinsic = require("./guard-intrinsic");
var _charCodeAt = intrinsic.uncurry(String.prototype.charCodeAt);
var _String = intrinsic.String;
var _defineProperty = intrinsic.defineProperty;

function _isCodeShape(c) {
  var n = c.length, i, ch, slash = -1;
  if (n < 3) return false;
  for (i = 0; i < n; i += 1) {
    ch = _charCodeAt(c, i);
    if (ch === 47) { if (slash !== -1) return false; slash = i; }
    else if (!((ch >= 97 && ch <= 122) || (ch >= 48 && ch <= 57) || ch === 45)) return false;
  }
  return slash > 0 && slash < n - 1;
}

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
 * alphanumerics and dashes); the construction throws a `TypeError`
 * otherwise, which catches an argument-order swap with the
 * `defineClass` subclasses' `(code, message)` convention at the call
 * site instead of shipping prose into a code-switching consumer.
 *
 * @example
 *   var bytes = Buffer.from([0x30, 0x80]);   // indefinite length -- not valid DER
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
    if (typeof c !== "string" || !_isCodeShape(c)) {
      throw new TypeError(
        "PkiError code must be a domain/reason string, got " + _String(c) +
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
 * Factory that produces a `PkiError` subclass with the standard shape. The
 * returned constructor takes
 * `(code, message)`, stamps `name`, sets an `is<Name>` flag, and exposes
 * a `.factory` static for the common `var _err = XxxError.factory` shape.
 * The `code` must be a `domain/reason` string (the base-class contract);
 * without `withCause`, a third constructor argument throws a `TypeError`
 * instead of silently discarding a cause the caller meant to thread.
 *
 * @opts
 *   withCause:  boolean,  // default false; constructor becomes (code, message, cause)
 *
 * @example
 *   // throws: my/bad-input -- raising the new error type IS what this shows
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
  _defineProperty(GeneratedError, "name", { value: name, configurable: true });
  GeneratedError.factory = function (code, message, arg3) {
    return new GeneratedError(code, message, arg3);
  };
  return GeneratedError;
}


var ConstantsError = defineClass("ConstantsError");

var Asn1Error = defineClass("Asn1Error", { withCause: true });

var CborError = defineClass("CborError", { withCause: true });

var OidError = defineClass("OidError", { withCause: true });

var PemError = defineClass("PemError", { withCause: true });

var CertificateError = defineClass("CertificateError", { withCause: true });

var CrlError = defineClass("CrlError", { withCause: true });

var SchemaError = defineClass("SchemaError", { withCause: true });

var CsrError = defineClass("CsrError", { withCause: true });

var Pkcs8Error = defineClass("Pkcs8Error", { withCause: true });

var CmsError = defineClass("CmsError", { withCause: true });

var OcspError = defineClass("OcspError", { withCause: true });

var TspError = defineClass("TspError", { withCause: true });

var AttrCertError = defineClass("AttrCertError", { withCause: true });

var CrmfError = defineClass("CrmfError", { withCause: true });

var Pkcs12Error = defineClass("Pkcs12Error", { withCause: true });

var CmpError = defineClass("CmpError", { withCause: true });

var PathError = defineClass("PathError", { withCause: true });

var SmimeError = defineClass("SmimeError", { withCause: true });

var CtError = defineClass("CtError", { withCause: true });

var ScepError = defineClass("ScepError", { withCause: true });

var TlsError = defineClass("TlsError", { withCause: true });

var C509Error = defineClass("C509Error", { withCause: true });

var MerkleError = defineClass("MerkleError", { withCause: true });

var CsrattrsError = defineClass("CsrattrsError", { withCause: true });

var EstError = defineClass("EstError", { withCause: true });

var CmcError = defineClass("CmcError", { withCause: true });

var TransportError = defineClass("TransportError", { withCause: true });

var JoseError = defineClass("JoseError", { withCause: true });

var AcmeError = defineClass("AcmeError", { withCause: true });

var TrustError = defineClass("TrustError", { withCause: true });
var ShbsError = defineClass("ShbsError", { withCause: true });
var HpkeError = defineClass("HpkeError", { withCause: true });
var KemError = defineClass("KemError", { withCause: true });
var SigstoreError = defineClass("SigstoreError", { withCause: true });
var InspectError = defineClass("InspectError", { withCause: true });
var WebauthnError = defineClass("WebauthnError", { withCause: true });
var LintError = defineClass("LintError", { withCause: true });
var KeyError = defineClass("KeyError", { withCause: true });

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
  ScepError:        ScepError,
  TlsError:         TlsError,
  C509Error:        C509Error,
  ShbsError:        ShbsError,
  HpkeError:        HpkeError,
  KemError:         KemError,
  SigstoreError:    SigstoreError,
  InspectError:     InspectError,
  WebauthnError:    WebauthnError,
  LintError:        LintError,
  MerkleError:      MerkleError,
  SmimeError:       SmimeError,
  CsrattrsError:    CsrattrsError,
  EstError:         EstError,
  CmcError:         CmcError,
  TransportError:   TransportError,
  JoseError:        JoseError,
  AcmeError:        AcmeError,
  TrustError:       TrustError,
  KeyError:         KeyError,
};
