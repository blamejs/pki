# Changelog

All notable changes to `@blamejs/pki` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.6.40 — 2026-09-05

Every verify verdict now reaches its caller as the object the verb built, and a list the toolkit assembles carries the entries the toolkit put in it.

### Fixed

- The verdicts of pki.attrcert.verify, pki.crl.verify, pki.csr.verify, pki.ct.verifySctWithLogList, pki.ct.verifySctList, pki.path.validate, pki.path.build, pki.pkcs12.verifyMac, pki.pkcs12.open, pki.webauthn.verify, pki.webauthn.verifyAssertion, pki.cmp.verify, pki.tsp.verify, pki.ocsp.verifyRequest and pki.sigstore.verifyBundle end the prototype lookup for then on themselves. An accessor installed there while a verification was pending could otherwise run with the verdict as its receiver and change what the caller reads.
- A list a verdict reports is appended to by defining the entry rather than assigning it, so a setter at the appended index cannot take the value and answer the read with something else. This covers the signers pki.cms.verify reports and the countersignatures under them, the per-SCT results and the distinct operators pki.ct.verifySctList counts its policy against, the per-certificate results pki.path.validate reports, the elements of a compound attestation pki.webauthn.verify returns, the certificate chain and transcript a pki.cmp session returns, and the signer identities pki.smime.verify reports.

## v0.6.39 — 2026-09-05

A verdict field is created with the verdict rather than written onto it afterward, so a value left on Object.prototype can no longer answer a question the verification never asked.

### Added

- The pki.ocsp.verify and pki.path.verifyOcspResponse verdicts carry valid, true only when status is good. Every failure these verbs detect already reports status unknown, so the boolean covers exactly the checks they run.
- The pki.cmc.verify verdict carries valid, true only for the issued outcome. Every other outcome, pending included, reads as false, with outcome, failInfo and pendToken unchanged.

### Changed

- The pki.ocsp.verify and pki.path.verifyOcspResponse verdicts report thisUpdate and nextUpdate as null, not undefined, when no response covered the certificate. Every path now reports both, so a reader gets the same shape whatever the verdict. Code testing them with === undefined should test == null.
- The container release workflow takes docker/setup-qemu-action v4.3.0.

### Fixed

- A verdict field is now created with the verdict rather than assigned onto it afterward, so a value left on Object.prototype cannot answer a read the verification never wrote. Three verdicts could report an affirmative that had not been established: an OCSP response whose signature does not verify, or that no authorized responder signs, contributed a good status through pki.ocsp.verify, pki.path.verifyOcspResponse and pki.path.ocspChecker, so pki.path.validate accepted a certificate whose revocation status was never determined; pki.cms.verify reported a signer as trusted when it had been given no trust anchors to chain to; and pki.crmf.verifyPop reported verified for a request carrying no proof of possession at all. pki.cmc.verify, pki.smime.verify and the pki.cmp session results carried the same construction and are fixed with them.
- A verdict also ends the prototype lookup for then, so an accessor installed there cannot rewrite it between the verification and the caller.
- A pki.cmp session transcript no longer reports a protection result on a request leg. A request records no verdict, and the snapshot read the field without asking whether the entry carried one, so a value left on Object.prototype was copied in and read back as a result the session never reached.
- The tables that decide how a signature is verified answer from their own entries alone. pki.cms.verify looked its signature scheme up in a table that inherits from Object.prototype, so a message could name an algorithm the toolkit does not implement and have the verification proceed under a descriptor left there. The dispatch tables in pki.cms.verify, pki.path.validate and the composite-signature resolver are fixed.

### Internal

- The test covering the implicit-rejection substitute content key chooses a ciphertext whose outcome it can predict. OpenSSL answers an RSA PKCS#1 v1.5 decode fault with a synthetic key whose length is drawn from the private key and the ciphertext, and a draw equal to the content-key length took the substitute out of the path, so the test failed about once in every few hundred runs.

## v0.6.38 — 2026-09-05

A trust anchor can name the namespace its root is trusted for, and pki.path.validate enforces it as the initial name-constraint state.

### Added

- A trust anchor passed to pki.path.validate or pki.path.build may carry nameConstraints: { permitted, excluded }, each an array of { tag, base } subtrees. They seed the RFC 5280 section 6.1.1(h)(i) initial permitted and excluded state, so a root a program trusts only for a namespace enforces that namespace even though its certificate states no nameConstraints extension. The anchor's subtrees intersect with an intermediate's own extension and with opts.initialPermittedSubtrees; excluded subtrees are a union.
- The pki.path.validate verdict reports anchorConstraints.nameConstraintsApplied, so a stored verdict distinguishes an anchor that named a namespace from one that did not, alongside the distrustAfterApplied and purposeTrustApplied it already carries.

### Fixed

- pki.path.validate and pki.path.build copy a directoryName subtree base and snapshot an iPAddress one before validating, and read opts.initialPermittedSubtrees and opts.initialExcludedSubtrees once rather than again for each trust anchor or candidate path tried. A caller mutating its own subtree list, entry or base while the path is still verifying signatures no longer changes the namespace the validation enforces; the subtrees that bind are the ones read at entry.
- A directoryName subtree base whose rdns is an accessor rather than a data property is refused. Its value was read once to check its shape and again to copy it, so an accessor could answer with a restrictive name the first time and an empty one the second, and an empty directoryName constraint matches every name.
- A subtree list that is a Proxy, that is sparse, or whose entries are accessors is refused, on a trust anchor and on opts.initialPermittedSubtrees and opts.initialExcludedSubtrees alike. Such a list answers its own length and index reads, so it could hold a restrictive subtree while reporting none and leave the namespace unenforced. A directoryName subtree is built from property descriptors alone, so nothing the caller supplies runs while the namespace is read: an accessor, own or inherited, is refused rather than invoked. It is a relative-name sequence of attribute lists and nothing deeper, so an array nested past that, including one that refers to itself, is a typed refusal, as is a hole, an entry the array does not own, an attribute that is not an object, or one lacking its own type and value. Each of those refusals is a configuration error reported wherever the anchor sits among several, rather than a name mismatch a different anchor could mask.
- A parsed certificate passed as a trust anchor is refused if it carries nameConstraints, the way one carrying purposes or distrustAfter already is. A certificate anchor cannot hold that metadata, so accepting it would have dropped the namespace and validated a leaf the anchor was meant to exclude.
- An anchor whose nameConstraints names a field other than permitted or excluded is refused rather than read as unconstrained, and its subtrees are checked while the anchor is normalized, so a malformed one is refused wherever that anchor sits among several rather than only once it is reached.

## v0.6.37 — 2026-09-05

A natively signed C509 certificate is refused when it writes an extension in the generic OID form that the registry can carry as an identifier.

### Fixed

- pki.schema.c509.parse refuses a natively signed certificate (c509CertificateType 2) that writes an extension as an OID and a DER value when a C509 registry identifier carries the same extension value. Draft section 3.7 reserves the generic form for re-encoded certificates, where it stays accepted. An extension whose OID has no registry identifier, and one whose value the compact encodings cannot represent under that certificate type's rules, both keep the generic form.
- pki.schema.c509.encode chooses an extension's form under the rules of the certificate type it is writing. It previously judged whether a value could be written compactly using the rules for a re-encoded certificate, so a natively signed certificate could be given a compact form its own decoder does not accept.
- pki.schema.c509.encode resolves an extension named only by its OID to the matching registry identifier. It looked the identifier up by name alone, so an extension supplied without one was written in the generic OID form even where a compact encoding carried it.
- pki.schema.c509 decides what belongs to the C509 registries by dotted OID rather than by the name pki.oid.register maps that OID to. Registering a different name for a built-in OID previously changed what the toolkit emitted for an unrelated certificate, and for commonName, a curve, ecPublicKey or an ECDSA signature algorithm it stopped a certificate converting to C509 at all.

## v0.6.36 — 2026-09-04

A natively signed C509 certificate is refused when it spells an algorithm generically instead of using the registry entry that names the same value.

### Added

- The subjectPublicKeyAlgorithm on a pki.schema.c509.parse result carries a parameters buffer when the certificate used a C509 registry integer, holding the parameters that entry names: the DER NULL for rsaEncryption and the namedCurve OID for an EC key. The generic OID forms already surfaced this field, so it is now present for every form that has parameters.

### Fixed

- pki.schema.c509.parse refuses a natively signed certificate (c509CertificateType 2) that writes an algorithm as an OID, or as an OID with parameters, when a C509 registry entry names that same value. Draft section 3.7 reserves the generic form for re-encoded certificates, where it stays accepted. An algorithm with no registry entry, and a registry OID whose parameters differ from the entry's, both keep the generic form.
- pki.schema.c509.parse refuses an rsaEncryption subjectPublicKeyAlgorithm that does not carry the DER NULL parameters RFC 3279 section 2.3.1 requires, including the bare OID form that carries none. The type-3 reconstruction previously emitted the OID and a NULL regardless, so the rebuilt DER described an algorithm identifier the certificate had not encoded.
- pki.schema.c509.encode writes an algorithm back as the form naming the same value. It previously chose the form by algorithm name alone, so re-encoding a certificate field by field could move an algorithm that carried no parameters onto a registry entry that names some, and could miss the entry for a key identified by its namedCurve parameters rather than by a curve name.
- pki.schema.c509.encode refuses a serialNumber, RSA modulus or RSA exponent that is not a BigInt. A string was previously read as hexadecimal and truncated to an even number of digits, so a caller passing "abc" received a certificate carrying the serial 0xab, and a number was silently converted. A missing modulus or exponent reached the emitter as an untyped fault rather than a c509 error naming the field.
- pki.schema.c509.encode reports every field it reads off a result as a typed c509 error naming that field. An extensions entry or an RDN that is not an object, an extension carrying neither an OID nor a registry name, an extension OID that is not a dotted-decimal string, and a keyUsageBits that is not a safe integer previously surfaced as a TypeError, a RangeError, or a fault from the OID or CBOR builders. An RDN value that is not a string is refused rather than converted, so a caller passing a number no longer receives a certificate naming its decimal spelling.
- pki.schema.c509.encode refuses a sparse extensions or rdns array. Array iteration skips a hole, so such a list emitted fewer entries than it held without reporting anything.

## v0.6.35 — 2026-09-04

Three redundant C509 spellings are refused, so a certificate has one encoding and an issuer signature cannot cover two different C509 byte strings.

### Fixed

- pki.schema.c509.encode refuses a serialNumberHex that is not an even-length hexadecimal string instead of decoding a prefix of it. An odd-length or partly non-hexadecimal value previously became a different, valid serial number without any error, which the encoder's own re-parse could not catch. The check applies whether the result is re-emitted from its preserved field bytes or built field by field, so a caller is told the value is malformed rather than having it quietly ignored.

### Security

- pki.schema.c509.parse refuses an unsigned bignum whose first octet is 0x00, including a value that is only that octet, so every number has exactly one C509 encoding (draft sec. 3.1.2). A zero serial previously had two spellings that reconstructed byte-identical DER, letting one issuer signature cover two distinct C509 certificates. The rule covers the certificate serial number, the authorityKeyIdentifier serial, and the RSA modulus and exponent.
- pki.schema.c509.parse refuses an RSA subjectPublicKey written as [modulus, 65537] instead of the bare modulus. Draft sec. 3.1.9 omits the array and the exponent when the exponent is 65537, so the array spelling of such a key is a second encoding of one certificate, reconstructing byte-identical DER. An RSA key with any other exponent still uses the array form.
- pki.schema.c509.parse refuses a notAfter written as the epoch 253402300799 rather than the CBOR simple value null. Draft sec. 3.1.5 encodes the no-expiration time 99991231235959Z as null, so the explicit epoch is a second spelling that reconstructs the same GeneralizedTime and therefore the same DER. A notBefore is unaffected, and pki.schema.c509.encode refuses that Date on notAfter instead of emitting a form the decoder rejects.

## v0.6.34 — 2026-09-04

An injected transport that does not return a promise is reported as a typed option error naming the option, in every client that accepts one.

### Changed

- pki.est, pki.acme, pki.cmp, and pki.scep reject with est/bad-input, acme/bad-input, cmp/bad-input, or scep/bad-input when opts.transport returns something that is not a promise of the response, instead of failing with a raw TypeError or a misleading response verdict. A transport returning any thenable is still accepted, and the documented signature now states the promise contract.

## v0.6.33 — 2026-09-04

pki.transport reports the RFC 9266 tls-exporter channel binding of a TLS 1.3 connection, so every connection the toolkit opens now carries the binding its protocol version defines.

### Added

- pki.transport.https reports tls.tlsExporter, the RFC 9266 channel binding of a TLS 1.3 connection (32 bytes, label EXPORTER-Channel-Binding, zero-length context), on its response and on the argument passed to a request body given as a function. It is null below TLS 1.3, where RFC 9266 sec. 2 also requires the RFC 7627 extended master secret that Node cannot confirm, and null when the socket cannot export. tls.tlsUnique is unchanged, so a connection carries exactly the binding its version defines.

## v0.6.32 — 2026-09-04

pki.est.simpleenroll and pki.est.simplereenroll accept a CSR builder, so an enrollment is signed over the tls-unique of the connection it is sent on (RFC 7030 sec. 3.5 channel binding).

### Added

- pki.est.simpleenroll(baseUrl, builder, opts?) and pki.est.simplereenroll(baseUrl, builder, opts?) accept a CSR builder (tls) -> csr | Promise<csr> for RFC 7030 sec. 3.5 channel binding. The builder receives the connection's { protocol, cipher, peerCertificate, tlsUnique } after the handshake and returns the certification request to POST on it, so pki.csr.sign can embed the base64 tls-unique as spec.challengePassword. A redirect or authentication retry re-runs the builder against the new connection (RFC 7030 sec. 3.2.1). Existing calls that pass a DER or PEM request are unchanged.

### Changed

- pki.est.simplereenroll performs its RFC 7030 sec. 4.2.2 subject and SubjectAltName identity check on each CSR a builder produces, inside the post-handshake callback and before that CSR is written. With a pre-built request the check still runs before the transport is called at all.

### Security

- A CSR builder combined with Digest authentication is refused (est/channel-binding-digest-unsupported) instead of sending an enrollment whose binding and Authorization header cannot both be correct: the Digest header is computed over the request body before the handshake the body must be bound to. A builder that throws fails the request (est/csr-builder-failed, with the cause attached) and a typed toolkit error it raises, such as requesting a binding on a TLS 1.3 connection where none exists, keeps its own code. No certification request is written to the wire in any of these cases, so an unbound or mis-bound enrollment is never sent. When an enrollment is retried across connections, the reported failure is the one that actually ended the attempt: a builder error is surfaced only where it caused the failure, so a later connection that fails on its own, for instance during TLS setup before the builder runs, reports that fault rather than an earlier builder error. A response is only ever read as an enrollment outcome when that request's own certification request was actually built and sent. Each request the client makes gets its own builder callback and its own state, so a callback belonging to an earlier request, including one a transport retained and ran late, can never supply the key or the error used to judge the request in flight. If an injected transport absorbs a builder failure, answers without requesting the body, or answers before the builder has finished, neither a 202 queued verdict nor an issued certificate is returned; the call fails closed instead, so enrollment progress is never reported for a request that never went out, and an issued certificate is never accepted against a key the request in flight did not carry.

## v0.6.31 — 2026-09-04

pki.transport reports the RFC 5929 tls-unique of a TLS 1.2 connection and accepts a request body built from it, so a caller can bind an EST enrollment to the TLS session it posts over (RFC 7030 sec. 3.5).

### Added

- pki.transport.https reports tls.tlsUnique on its response (the RFC 5929 tls-unique of a TLS 1.2 connection; null on TLS 1.3, where RFC 5929 defines none) and accepts a request body given as a function (tls) -> bytes, invoked after the handshake and before the body is written. A caller builds a channel-bound CSR from tls.tlsUnique inside the callback and posts it on the same connection (RFC 7030 sec. 3.5), passing the binding to pki.csr.sign as spec.challengePassword. The callback may return a promise, so the CSR can be signed with pki.csr.sign while the connection is held open. A callback that throws, rejects, omits its return, or returns any value that is not bytes or a string fails the request closed rather than posting an empty enrollment; an explicit empty string remains an intentional empty body.

### Fixed

- pki.est.challengePasswordFromTlsUnique now carries reference documentation. It returns a pre-encoded DER challengePassword Attribute, which pki.csr.sign refuses in spec.attributes (csr/bad-input); to sign a channel-bound request, pass the base64 binding as spec.challengePassword, which produces the identical attribute. The two forms are alternatives, and the reference now says so rather than leaving the composition to be discovered.

## v0.6.30 — 2026-09-04

Reference documentation is corrected across the toolkit: a mistyped signed-attribute field name, and options and return fields the code accepts or returns that the reference had omitted.

### Changed

- Options and return fields the code accepts or returns are now documented across pki.cms, pki.tsp, pki.pkcs12, pki.hpke, pki.path, pki.ocsp, pki.asn1, pki.est, pki.acme, and pki.webauthn. In particular, pki.webauthn.verifyAssertion is documented as checking the challenge and origin when expectedChallenge / expectedOrigin / expectedTopOrigin are supplied with clientDataJSON.
- Reference prose across the toolkit and the documentation site is reworded for consistency.

### Fixed

- pki.smime.sign documented additionalSignedAttributes as [{ oid, values }]; the code reads the type field, so a caller following the reference would pass an unrecognized field. The correct form is [{ type, values }].
- pki.ocsp.buildErrorResponse is documented as returning a Buffer; the signature previously showed Buffer | string, but the verb has no PEM option and every path returns DER.
- The pki.schema.all example output lists csrattrs, which the enumeration returns between cmp and ocsp-request.
- The pki.acme.client method list documents updateAccount and listOrders, which the client returns.
- pki.tsp.verify now includes policyName on a failure verdict; it already returned the resolved policy name on a valid verdict and the raw policy on both, so a refused token carries the same descriptive fields as a valid one.

## v0.6.29 — 2026-09-03

The EST, ACME, and CMP clients reach a CA through a forward HTTP proxy, with the same opts.proxy the SCEP client already accepts.

### Added

- pki.est.cacerts / simpleenroll / simplereenroll / serverkeygen / csrattrs / fullcmc, pki.acme.client, pki.cmp.transfer, and the pki.cmp.session client (which forwards it to every enrollment, polling, revocation, and confirmation leg) accept opts.proxy = { url, auth?, tls? } to reach the CA through a forward HTTP proxy, the same option pki.scep accepts. The origin TLS is negotiated inside the proxy's CONNECT tunnel under the identical origin trust policy; Basic authentication (RFC 7617) is sent only over an https:// proxy verified against proxy.tls, and an http:// proxy is tunnel-only. The option is deep-copied at the call so a later change to the caller's object cannot alter the proxy in use.

## v0.6.28 — 2026-09-02

pki.path.build returns the best accepted path when the candidate cap is reached during policy ranking, instead of discarding it.

### Fixed

- pki.path.build with userInitialPolicySet no longer throws path/build-limit after it has already accepted a valid path. When the candidate cap is reached during policy ranking, it returns the best-policy accepted path (forward and reverse directions), and candidatesConsidered reflects the full expansion count. It throws path/build-limit only when no valid path was accepted before the cap. This restores the pre-0.6.26 behavior for a policy set that no single path fully covers under a bounded search.

## v0.6.27 — 2026-09-02

The SCEP client can reach a CA through a forward proxy, with Basic authentication over an https proxy.

### Added

- pki.transport gains forward-proxy support: request.proxy = { url, auth?, tls? } opens a CONNECT tunnel to the proxy and negotiates the origin's TLS inside the tunnel under the same trust anchors and rejectUnauthorized as a direct connection, so the proxy relays the encrypted origin session without being able to read it and cannot substitute the origin certificate.
- Basic proxy authentication (RFC 7617) is sent only over an https:// proxy, whose certificate is verified against proxy.tls (its own trust anchors, separate from the origin's), so credentials ride the authenticated TLS-to-proxy channel. A plaintext http:// proxy is tunnel-only; supplying auth for one is refused with transport/proxy-auth-requires-tls rather than exposing the credentials to the proxy hop. A proxy certificate that does not verify is transport/proxy-tls-failed.
- pki.scep threads opts.proxy through every network verb (getCACaps, getCACert, getNextCACert, enroll, renew, getCert, getCrl). A malformed proxy option (scep/bad-proxy), a non-2xx CONNECT (scep/proxy-connect-failed), a 407 with no or rejected credentials (scep/proxy-auth-required, scep/proxy-auth-failed), and a plaintext-http origin (scep/insecure-url) each fail closed. Digest proxy authentication is not included in this release.

## v0.6.26 — 2026-09-02

pki.path.build can prefer the certification path whose policies satisfy a caller-supplied policy set.

### Added

- pki.path.build now uses opts.userInitialPolicySet to select the best-policy valid path across trust anchors and intermediates (RFC 4158 sec. 4), not only to constrain pki.path.validate's policy processing. It returns the accepted path whose user-constrained policy set best satisfies the requested set, with the existing candidate ordering as a deterministic tie-break; validate still gates every path. An anyPolicy entry is unconstrained (first accepted path); the ranking is bounded by maxCandidatesConsidered; a malformed userInitialPolicySet is refused with path/bad-input.

## v0.6.25 — 2026-09-02

pki.path.build can search from a trust anchor toward the leaf, not only from the leaf toward an anchor.

### Added

- pki.path.build accepts opts.direction: "forward" (default), "reverse" (search from a trust anchor toward the leaf, RFC 4158 sec. 3.1), or "auto" (pick by first-hop fan-out). Every direction hands each assembled path to pki.path.validate, so the direction changes only search order, never which paths are accepted; the anchor is excluded from the returned path. Reverse building is pool-only and does not combine with fetchAia.

## v0.6.24 — 2026-09-02

A caller option of an unexpected type now yields the module's typed error, not a native TypeError.

### Fixed

- An option of an unexpected type passed to a build, sign, export, or enrollment verb (a BigInt, an object with no primitive form, or one whose Symbol.toPrimitive throws) is reported as the module's typed bad-input error instead of a native TypeError leaking from a diagnostic string, a lookup-table key, a Date conversion, or a numeric coercion. This covers the timestamp, OCSP, CMP, CMC, SCEP, EST, ACME, PKCS#12, S/MIME, attribute-certificate, HPKE, Certificate Transparency, and Sigstore APIs.

## v0.6.23 — 2026-09-01

The SCEP client can carry a PKIOperation over HTTP GET for a CA that does not support POST.

### Added

- pki.scep.enroll / renew / getCert / getCrl accept httpMethod: "POST" (default) or "GET". Under "GET" the client sends the PKIOperation message as GET SCEPPATH?operation=PKIOperation&message=<base64-CMS> with no body (RFC 8894 sec. 4.1), for a CA that does not advertise POST support. POST stays the default and the recommended transport; a bad httpMethod is refused with scep/bad-input.

## v0.6.22 — 2026-09-01

pki.acme.client gains scheduleRenewal, the RFC 9773 auto-sleeping certificate-renewal loop.

### Added

- pki.acme.client(...).scheduleRenewal(certDer, { random, shouldStop, renew, maxChecks, maxWait, longTermRetrySeconds, temporaryBaseSeconds }) is the RFC 9773 sec. 4.1 auto-sleeping renewal loop. It composes renewalWindow and the client's injectable sleep/clock: fetch the ARI decision, sleep until the sooner of the selected instant and the clamped Retry-After, refetch until renewNow, then resolve { reason: "renew-now", decision }. It resolves { reason: "expired" } once the certificate passes its notAfter (a client must not check RenewalInfo after expiry, RFC 9773 sec. 4.3), { reason: "stopped" } when shouldStop() signals the certificate is replaced, and { reason: "budget" } at the optional maxChecks or maxWait bound. An invalid suggested window or a transport error retries on the sec. 4.3.3 schedule, with a 5xx backing off exponentially from temporaryBaseSeconds and every other error waiting longTermRetrySeconds (default six hours). A supplied renew(decision) callback is awaited at renew-now instead of resolving, and returning a new certificate DER reschedules on it.

## v0.6.21 — 2026-09-01

WebCrypto and the signing and format builders refuse an algorithm, curve, digest, or profile name that collides with an inherited Object.prototype property name.

### Fixed

- pki.webcrypto (generateKey, sign, verify, encrypt, decrypt, deriveBits, deriveKey, wrapKey, unwrapKey, importKey, encapsulateBits, decapsulateBits) refuses an algorithm name or namedCurve that collides with an inherited Object.prototype property name, returning webcrypto/not-supported instead of a bare Node error. The digest, PBMAC1 PRF, CMP body, PKCS#12 MAC hash, PBES2 PRF, and lint-profile lookups behind pki.tsp.sign, pki.cmp.build, pki.pkcs12.build, pki.key.encrypt, pki.lint.certificate, and the RSA-PSS and C509 builders are hardened the same way, each returning the verb's typed error for such a name.

## v0.6.20 — 2026-09-01

A vulnerable build-time dependency is refreshed; it is not part of the published package.

### Security

- browserslist, a transitive development dependency of the fuzzing harness, is updated from 4.28.4 to 4.28.8, clearing GHSA-73wf-gq98-2v4g and GHSA-c83g-rgw3-j3cx (both High). browserslist is a build-time and test-time dependency and is not part of the published package.

## v0.6.19 — 2026-09-01

pki.scep.build issues the CA-side CertRep response, so the toolkit produces the SCEP certification-authority reply the client enrollment verbs consume.

### Added

- pki.scep.build({ messageType: "CertRep", pkiStatus, transactionId, recipientNonce, ... }) issues a SCEP CertRep response (RFC 8894 sec. 3.3.2). SUCCESS takes certificates (and/or crls, leaf identified by content since the CMS certificate SET is DER-ordered) plus the requester's recipient certificate and the CA signer; the issued certificates ride a certs-only SignedData inside a pkcsPKIEnvelope encrypted to the requester. FAILURE takes a failInfo (and optional failInfoText) and PENDING takes neither; both omit the pkcsPKIEnvelope and are signed detached. recipientNonce (echoing the request's senderNonce) and transactionId are required; a missing failInfo on a FAILURE, a SUCCESS without a certificate/CRL or recipient, an envelope field on a FAILURE or PENDING, or an unknown pkiStatus or failInfo is refused with a typed scep/bad-input.

### Fixed

- An enumerated option whose value collides with an inherited Object.prototype property name, such as a pkiStatus, contentEncryptionAlgorithm, macAlgorithm, digestAlgorithm, PKCS#8 cipher, or ACME resource kind of "toString" or "constructor", is now refused with the verb's own typed bad-input error across pki.scep.build, pki.cms.encrypt, pki.cms.authenticate, pki.key.encrypt, pki.acme.validate, and pki.acme.assertTransition. Such a value previously resolved to the inherited method and the call surfaced an unrelated error, and pki.acme.validate accepted the kind and returned without checking any field.
- pki.scep.build now requires a primitive-string pkiStatus. A boxed String or an object that coerces to a status name is refused with scep/bad-input, instead of building a CertRep whose signed pkiStatus attribute claims SUCCESS while the pkcsPKIEnvelope that a SUCCESS response requires is absent.

## v0.6.18 — 2026-09-01

pki.cms.encrypt and pki.cms.decrypt envelope to and open a composite ML-KEM recipient, extending the CMS KEMRecipientInfo arm to the hybrid post-quantum key-establishment algorithms.

### Added

- pki.cms.encrypt accepts a recipient certificate carrying a composite ML-KEM public key (id-MLKEM768-* or id-MLKEM1024-*, twelve algorithms pairing ML-KEM-768/1024 with RSA-OAEP 2048/3072/4096, ECDH over P-256/P-384/P-521 and brainpoolP256r1/P384r1, X25519, or X448) and emits an id-ori-kem KEMRecipientInfo: the composite as the kem algorithm with absent parameters, the composite ciphertext, HKDF-SHA256 as the kdf, and AES-256 key wrap with a 32-octet key-encryption key (RFC 9629 / RFC 9936). The recipient certificate must assert the keyEncipherment key usage.
- pki.cms.decrypt opens a composite ML-KEM KEMRecipientInfo with the recipient's composite PKCS#8 key, recovering the content-encryption key through the same KDF and unwrap. A wrong key, a tampered ciphertext, or a traditional-component decapsulation failure returns the uniform cms/decrypt-failed verdict, never a distinguishing error.

## v0.6.17 — 2026-09-01

pki.scep.getCert and pki.scep.getCrl retrieve an already-issued certificate or a CA's CRL over SCEP, sending RFC 8894 GetCert and GetCRL queries and reading the result out of the CA's signed CertRep.

### Added

- pki.scep.getCert(baseUrl, opts) retrieves an issued certificate over SCEP (RFC 8894 sec. 3.3.4). Name the target by { certificate } (the certificate whose issuer and serial identify it) or by { issuer, serialNumber } directly; the serial accepts a BigInt, a number, or a hex string. The CA response is verified against caCert (or responderCert), its recipientNonce must echo the query's fresh senderNonce, and the returned certificate is matched to the requested issuer and serial before it is handed back. A response carrying no matching certificate throws scep/cert-not-found; more than one throws scep/ambiguous-cert.
- pki.scep.getCrl(baseUrl, opts) retrieves a CA's CRL over SCEP (RFC 8894 sec. 3.3.4), named the same way as getCert. The response is authenticated identically, and the returned CRL is bound to the query: getCrl returns the CRL whose issuer matches the requested CA, throwing scep/no-crl when the response carries no such CRL and scep/ambiguous-crl when it carries more than one. Per RFC 8894 sec. 2.7 a client should compose a GetCRL only when the CA supports neither a CRL distribution point nor HTTP access; prefer those and pki.schema.crl.parse where available.
- pki.scep.build and pki.scep.parse now handle the GetCert (messageType 21) and GetCRL (messageType 22) queries: a pkcsPKIEnvelope carrying an IssuerAndSerialNumber (a CMS SEQUENCE of the issuer Name and the certificate serial), signed under the transaction attributes (RFC 8894 sec. 3.3.4).

### Changed

- pki.scep.parse accepts every messageType the RFC 8894 registry defines, including GetCert and GetCRL. A messageType outside the registry is still refused with scep/bad-message-type.

## v0.6.16 — 2026-09-01

pki.scep.enroll and pki.scep.renew poll a PENDING enrollment to its issued certificate, sending RFC 8894 CertPoll requests until the CA answers or a bounded poll-count and wait budget is exhausted.

### Added

- pki.scep.build and pki.scep.parse now handle the CertPoll (GetCertInitial, messageType 20) request: a pkcsPKIEnvelope carrying an IssuerAndSubject (the CA's subject name and the request's subject name), signed under the transaction attributes with the original transactionID (RFC 8894 sec. 3.3.3).
- pki.scep.enroll and pki.scep.renew poll a PENDING response to a terminal status. New options bound the loop: pollCount (maximum CertPoll requests, default 5), maxTotalWait (total Retry-After sleep budget in seconds), sleep (an injectable (ms) -> Promise sleeper), and onRetryAfter (an observer of each delay). A budget exhausted with no terminal response throws scep/poll-exhausted carrying the transactionId to resume with. For a deployment whose request is encrypted to a separate RA certificate, issuerCert names the issuing CA the CertPoll must carry (default caCert).

### Changed

- pki.scep.enroll and pki.scep.renew poll by default when the CA answers PENDING: a PENDING enrollment now resolves to the issued certificate or throws, rather than returning { status: "PENDING" } for the caller to retry. Pass pollCount: 0 to restore the single-shot PENDING return and drive the retry yourself.

## v0.6.15 — 2026-09-01

Verifying a Sigstore bundle no longer matches a pinned identity against a non-text subjectAltName value; the value is surfaced as null so the policy fails closed instead of comparing raw bytes. The library source also ships without its explanatory comments, keeping the JSDoc that generates the API reference and the SPDX license headers.

### Changed

- The library source no longer carries explanatory comments; the wiki-generating JSDoc blocks and SPDX license headers are unchanged, so the installed package is smaller.
- Internal cleanup with no observable difference: a dead helper was removed, and the android-safetynet certificate decoder now passes its message factory to the base64 input guard rather than an error class.

### Fixed

- Verifying a Sigstore bundle no longer reads a non-text subjectAltName otherName value as the certificate identity. The value is surfaced as null, and an identity policy that pins the san field fails closed against it. A value whose raw bytes matched a pinned identity could previously satisfy the policy.

## v0.6.14 — 2026-08-31

pki.scep.getNextCACert retrieves a SCEP CA's next (rollover) certificate and authenticates it against the current CA key, so a client can obtain and hold the CA certificate to install before the current one expires.

### Added

- pki.scep.getNextCACert(baseUrl, opts) performs the RFC 8894 sec. 4.7 GetNextCACert exchange for CA key rollover: a GET for the CA's next certificate whose SignedData response is verified and pinned to the current CA certificate (opts.caCertificate) before the next CA certificate(s) are returned in certificates. opts.caCertificate is required, and a response signed by any key other than the current CA is refused (scep/untrusted-signer), so a rollover certificate that would become a future trust anchor is never returned without authentication.

## v0.6.13 — 2026-08-31

pki.sigstore.verifyBundle now reports which transparency-log entry attested a bundle: the verdict carries `logIndex` and `logId` so a caller can locate the exact Rekor record it verified against.

### Added

- pki.sigstore.verifyBundle's verdict carries `logIndex` (the attested Rekor entry's global log index) and `logId` (the log's key id, hex) beside `integratedTime`, so a caller can fetch or audit the exact transparency-log record the bundle was verified against instead of re-deriving it.

## v0.6.12 — 2026-08-31

Three verify verbs that returned a bare boolean now return a verdict object naming the checks they had hidden, a canonical `valid` field is present on every object verify verdict so `if (res.valid)` reads the same everywhere, and revocation, digest, and provenance data omitted before is surfaced.

### Added

- Every object verify verdict now carries a canonical `valid` boolean beside its existing terminal, so `if (res.valid)` reads the verdict the same way across the toolkit: pki.sigstore.verifyBundle, pki.csr.verify, pki.crmf.verifyPop (top and per message), pki.attrcert.verify, pki.webauthn.verify, pki.webauthn.verifyAssertion, pki.ocsp.verifyRequest (`valid` is `signed && signatureValid`), pki.ct.verifySctList (`valid` is `policyOk`), and pki.pkcs12.open (`valid` is the store's verified integrity: the password MAC for a password store, or the CMS signature for a public-key store). The existing fields (`verified`, `policyOk`, `macVerified`, and the rest) are unchanged. The multi-state string verdicts (pki.ocsp.verify `status`, pki.scep `status`) keep their terminal and do not gain a `valid` alias, since a boolean cannot carry their states.
- pki.ocsp.verify and pki.path.verifyOcspResponse surface `revocationTime` (the revocation instant) beside `revocationReason` on a revoked verdict, for long-term validation.
- pki.cms.verify's primary signer node carries `digestAlgorithm`, the digest the countersignature node already reported, so a caller reading a signer's verdict learns it without a second parse.
- pki.sigstore.verifyBundle carries `predicateTypeChecked`, so a caller that did not pin `opts.predicateType` learns the in-toto predicate went unverified rather than assuming it was checked.

### Changed

- pki.crl.verify returns `{ valid, issuerMaySign, signatureValid, issuer, code?, reason? }` instead of a bare boolean. The boolean hid whether the signing certificate was this CRL's issuer and asserted `cRLSign` in its keyUsage, so a CRL minted under an end-entity certificate of the same CA verified as that CA's own. `valid` is `issuerMaySign && signatureValid`; the signature is now checked even when the issuer may not sign, so `signatureValid` is always reported. To upgrade, read `res.valid` where you read the boolean. This is a silent break for an unmigrated `if (await pki.crl.verify(...))`, which now reads an object as always-true.
- pki.pkcs12.verifyMac returns `{ valid, macAlgorithm, macAlgorithmName, iterationCount }` instead of a bare boolean, so a caller can reject a legacy SHA-1 integrity MAC by inspecting `macAlgorithmName` rather than accepting any authenticated store. To upgrade, read `res.valid`. Silent break for an unmigrated boolean test.
- pki.ct.verifySctWithLogList returns `{ valid, logId, logIdHex, operator, logState, timestamp }` instead of a bare boolean, surfacing which trusted log accepted the SCT and when for a policy decision. To upgrade, read `res.valid`. Silent break for an unmigrated boolean test.

## v0.6.11 — 2026-08-31

pki.path.validate and pki.tsp.verify now take the trust store under the option name trustAnchors, the spelling the other verify verbs already use, accepting one anchor or an array; and pki.acme.client gains opts.resignKeys, which re-signs a request under an alternative account-key algorithm when a CA reports badSignatureAlgorithm.

### Added

- pki.acme.client accepts opts.resignKeys, an ordered array of { alg, key } alternatives for the account key (RFC 8555 section 6.2). When a CA rejects the account's JWS algorithm with a badSignatureAlgorithm error and lists the algorithms it supports, the client re-signs the request once with the first listed alternative the CA supports and retries. Each key is a CryptoKey for the same account key material under that algorithm, so the account's registered public key still verifies the re-signed request. The caller's order selects the algorithm and the CA's list only filters it, so a spoofed badSignatureAlgorithm cannot force a weaker algorithm (RFC 8555 section 10). Without the option, or when no listed algorithm is a caller alternative, the error surfaces unchanged.

### Changed

- pki.path.validate and pki.tsp.verify read the trust anchor from opts.trustAnchors, the same option the other verify verbs take. It accepts a single anchor tuple or root certificate, or a non-empty array of them; when several are supplied, pki.path.validate selects the anchor that issued the path's top certificate, and a one-element array reproduces the previous single-anchor result exactly. The former singular opts.trustAnchor is removed and is refused as an unknown option rather than silently ignored, so a stale caller gets a named error instead of an unanchored valid result. To upgrade, pass { trustAnchors: anchor } (or { trustAnchors: [a, b] }) where you passed { trustAnchor: anchor }.

## v0.6.10 — 2026-08-31

pki.est computes a response body's length from a single read of res.body, shared by one helper across every verb, so a caller-supplied transport whose res.body getter changes between reads cannot desync the type check from the measured length.

### Fixed

- pki.est reads a response body's length from a single access of res.body rather than re-reading it across the null / string / BufferSource type-check arms. A caller-supplied transport whose res.body getter returns different values across reads could otherwise size the body from a different value than the one the type check classified. The five identical per-verb length computations are consolidated into one shared helper that reads res.body once.

## v0.6.9 — 2026-08-31

pki.cmp.verify holds a received PKIMessage to the RFC 9483 sec. 3.5 header rules, and pki.path.build and pki.est read a response body an injected transport returns as any BufferSource, not only a Node Buffer.

### Changed

- pki.cmp.verify holds a received PKIMessage to the RFC 9483 sec. 3.5 receiving-side header rules once its protection verifies: the pvno must be cmp2000(2) or cmp2021(3), the transactionID must be present, and the senderNonce must be present and carry at least 128 bits. A message failing any of these is a fail-closed verdict (cmp/unsupported-version, cmp/bad-transaction-id, cmp/bad-sender-nonce). A cmp1999(1) message stays valid RFC 9810 syntax that pki.cmp.parse still decodes; the profile refuses it only on receipt. pki.cmp.session applies these checks to every response and additionally refuses a waiting ip/cp/kup CertResponse that carries failInfo (RFC 9483 sec. 4.4). A conformant peer is unaffected; a peer that omits a required header field is now refused.

### Fixed

- pki.path.build's opt-in AIA caIssuers fetch reads a certificate an injected transport returns as any BufferSource (a Uint8Array, a raw ArrayBuffer, a DataView), not only a Node Buffer. A typed-array body was coerced to a comma-joined string and failed to parse, silently dropping an AIA-discoverable intermediate from the built path; it is now re-viewed through the byte guard and parsed from its bytes.
- Every pki.est network verb reads a response body an injected transport returns as any BufferSource, not only a Node Buffer or a string. The transfer decode, the multipart splitter, the response-size checks, and the error diagnostic take the raw bytes through the byte guard, so a cacerts, enrollment, or serverkeygen response delivered in a typed array is parsed and sized from its bytes.

## v0.6.8 — 2026-08-31

pki.cmp.build assembles the ccr cross-certification request body (RFC 9810 sec. 5.3.11), and the ACME client accepts a response body an injected transport returns as any BufferSource, not only a Node Buffer.

### Added

- pki.cmp.build assembles the ccr cross-certification request body (RFC 9810 sec. 5.3.11): a CertReqMessages under PKIBody [13], the request one certification authority sends to have another certify its existing public key. It carries the same certificate template and proof-of-possession as an ir or cr, and refuses the private-key-transport encryptedKey proof-of-possession, since a ccr does not send the requesting CA's private key. It is a CertReqMessages at the sec. 5.3.11 normative floor, so it requires no Appendix D.6 profile field and does not enforce the optional D.6 single-request cardinality: a multi-request ccr builds and round-trips, and a producer that follows App. D.6 sends one cross-certificate per message by its own policy.

### Changed

- pki.schema.cmp.parse and pki.cmp.build no longer enforce the App. D.6 single-CertResponse cardinality on a ccp cross-certification response. A CertRepMessage is SIZE (1..MAX) and App. D.6 is optional, so a multi-response ccp is parsed and built at the RFC 9810 sec. 5.3.12 normative floor, matching the new ccr treatment. The sec. 5.3.12 no-private-key restriction is unchanged.

### Fixed

- The ACME and SCEP clients read a response body an injected transport returns as any BufferSource (a Uint8Array, a raw ArrayBuffer, a DataView), not only a Node Buffer or a string. Both the response-size check and the body decode take its raw bytes through the byte guard, so a BufferSource response is measured and parsed from its bytes rather than from a comma-joined string, and the size check accepts the same forms the decode does.

## v0.6.7 — 2026-08-31

pki.scep gains the SCEP HTTP client verbs (RFC 8894): getCACaps, getCACert, enroll, and renew drive a certificate enrollment against a SCEP CA over the shipped pkiMessage codec.

### Added

- pki.scep.getCACaps(baseUrl, opts) queries a SCEP CA's advertised capabilities (RFC 8894 sec. 3.5) and returns the parsed keyword set; pki.scep.parseCapabilities(text) exposes the parser directly. The response is unauthenticated (sec. 7.5), so the verb reports what the CA claims without downgrading on it; pass expectSCEPStandard or requireStrongProfile to fail closed when the strong profile is absent.
- pki.scep.getCACert(baseUrl, opts) retrieves the CA certificate, either a single DER certificate or a certs-only chain (RFC 8894 sec. 4.2). Pass an out-of-band expectedFingerprint (a hex string or Buffer, SHA-256 by default) and a returned certificate must match it or the response is refused (RFC 8894 sec. 2.2); omitting it returns the certificates for the caller to authenticate.
- pki.scep.enroll(baseUrl, opts) and pki.scep.renew(baseUrl, opts) POST a PKCSReq or RenewalReq to ?operation=PKIOperation and read the CertRep. The response signature is authenticated against the CA certificate and its recipientNonce must echo the request's senderNonce; on SUCCESS the issued certificate is selected out of the response by SubjectPublicKeyInfo match, a FAILURE throws scep/enrollment-failed carrying the CA's failInfo, and a PENDING returns { status: "PENDING", transactionId } to retry. The content key is transported under RSAES-OAEP, so the CA certificate must be an RSA keyEncipherment certificate.

### Fixed

- The EST, SCEP, and ACME client verbs override the mTLS client certificate, key, and pinned servername on a cross-origin redirect rather than omitting them. A transport constructed with a default client credential (for example pki.transport.https({ tls: { cert, key } })) no longer presents that credential to the redirected origin.

## v0.6.6 — 2026-08-31

pki.kem establishes a shared secret with composite ML-KEM (draft-ietf-lamps-pq-composite-kem): a post-quantum ML-KEM hybridized with a traditional RSA-OAEP, ECDH, X25519, or X448, so the secret holds if either component is later broken.

### Added

- pki.kem.encapsulate(publicKey) establishes a 256-bit shared secret for a recipient's composite ML-KEM SubjectPublicKeyInfo, returning the secret and a ciphertext to send to the recipient (draft-ietf-lamps-pq-composite-kem).
- pki.kem.decapsulate(privateKey, ciphertext) recovers the shared secret from a composite ML-KEM ciphertext and the composite PKCS#8 private key. The twelve algorithms pair ML-KEM-768 and ML-KEM-1024 with RSA-OAEP 2048/3072/4096, ECDH over P-256/P-384/P-521 and brainpoolP256r1/P384r1, X25519, and X448.

## v0.6.5 — 2026-08-30

pki.cmp.build assembles a CMP key-recovery request (krr) body: a CertReqMessages under PKIBody tag [9], the key-recovery counterpart of an initialization request (RFC 9810 sec. 5.3.7).

### Added

- pki.cmp.build accepts a { krr } body arm (RFC 9810 sec. 5.3.7): a key-recovery request, a CertReqMessages built through pki.crmf.build under PKIBody tag [9], identical in syntax to an initialization request. The proof-of-possession key is a key field on the arm spec, and any proof-of-possession arm the CRMF builder produces is permitted, including a private-key-transport encryptedKey proof.

## v0.6.4 — 2026-08-30

The ACME client gains account update and order listing: pki.acme.client updates an account's contacts (RFC 8555 sec. 7.3.2) and fetches the account's orders list, following the paginated Link: rel="next" chain (sec. 7.1.2.1).

### Added

- pki.acme.client(...).updateAccount(opts) updates an ACME account (RFC 8555 sec. 7.3.2): a kid-signed POST to the account URL that sets opts.contact (RFC 6068 mailto hygiene applies; an empty array clears all contacts) and returns the resulting account object. The fields the server MUST ignore are refused at the door with a typed acme/bad-input naming the correct path: status (use deactivateAccount, sec. 7.3.6 is the only client-settable status), termsOfServiceAgreed (not client-updatable; a changed-terms CA answers a request with a userActionRequired problem, surfaced as acme/server-problem, rather than a client re-agreement), orders (server-assigned), and externalAccountBinding (not client-updatable). An unrecognized option is refused rather than sent.
- pki.acme.client(...).listOrders(ordersUrl, opts?) fetches an account's orders list (RFC 8555 sec. 7.1.2.1) via POST-as-GET and returns { orders, pages, truncated }: orders is the aggregated array of order URLs, pages is how many pages were read, and truncated is true when the list was cut short by the page cap. It follows the sec. 7.1.2.1 Link: rel="next" pagination, bounded by opts.maxPages (default 50) and a visited-page dedupe so a looping or over-long next chain stops rather than fetching without end. Because the next header is delivered over TLS but not signed, and it steers an account-key-signed POST-as-GET, each next is https-gated and confined to the orders URL's own origin; an off-origin or non-https next is refused with acme/bad-link, and two distinct next targets (a singleton relation, RFC 8288 sec. 3.3) are ambiguous and refused.
- pki.acme.updateAccount(opts) is a new message-layer builder (a top-level export alongside pki.acme.deactivate): it builds the kid-signed account-update JWS the client composes, so the message layer is usable without the stateful client.

### Changed

- The RFC 8288 Link response-header parser is now relation-parameterized: the sec. 7.4.2 alternate certificate-chain reader and the sec. 7.1.2.1 next orders-page reader share one hardened scan (byte cap, control-octet reject, relation-type well-formedness, anchor-context check, resolve, https gate, origin gate, and dedupe), so the same untrusted-header defenses cover both relations. Behavior for the alternate relation is unchanged.

## v0.6.3 — 2026-08-30

pki.cms builds and reads certs-only certificate-management messages: a degenerate CMS SignedData that conveys certificates and CRLs without signing anything (RFC 8551 sec. 3.8).

### Added

- pki.cms.certsOnly(certs, opts?) builds a certs-only certificate-management message (RFC 8551 sec. 3.8): a degenerate CMS SignedData with version 1, an empty digestAlgorithms and signerInfos, an id-data encapContentInfo with the eContent absent, and the caller's certificates in certificates [0] and any CRLs in crls [1], both DER-sorted and deduplicated. certs is a certificate or an array of them (DER Buffer or PEM string), and opts.crls carries CRLs the same way; at least one certificate or CRL is required. Each entry is parsed as a real X.509 certificate or CertificateList before it is embedded, so a non-certificate, a non-CRL, or a tagged CertificateChoices alternative is refused with a typed cms/bad-input rather than emitted. opts.pem returns a PEM string instead of DER.
- pki.cms.parseCertsOnly(input, opts?) reads a certs-only message (DER Buffer or PEM) and returns { certificates, crls } as raw DER. It requires a degenerate SignedData (id-data with no eContent, empty signerInfos) and refuses a non-degenerate structure with cms/not-certs-only. Unlike the RFC 5272 Simple PKI Response that pki.est.parseCertsOnly reads, a CRL-only message is accepted (RFC 8551 sec. 3.8 conveys certificates and/or CRLs); a message carrying neither is refused. opts.maxCerts caps the number of certificates and CRLs parsed and returned, a bound on an untrusted bundle.
- pki.cms.isCertsOnly(input) reports whether input is a certs-only message structurally, returning true for a SignedData with an id-data content, absent eContent, and empty signerInfos, and false for any other well-formed CMS. Undecodable bytes throw a typed CmsError.
- pki.smime.buildCertsOnly(certs, opts?) wraps a certs-only message in one application/pkcs7-mime; smime-type=certs-only; name=smime.p7c S/MIME entity (RFC 8551 sec. 3.2.1), with the certs-only DER as the base64 body. It accepts the same certificate and opts.crls inputs as pki.cms.certsOnly.

## v0.6.2 — 2026-08-30

pki.scep builds and reads SCEP (RFC 8894) enrollment messages: a client assembles a PKCSReq or RenewalReq request and parses a CA's response back to its verified transaction attributes and issued certificates.

### Added

- pki.scep.build(spec) assembles a SCEP request pkiMessage (RFC 8894 sec. 3). Given a PKCS#10 certification request as messageData, a recipient CA certificate, and a signer { cert, key }, it verifies the request's own proof-of-possession, encrypts it to the CA as the inner EnvelopedData (pkcsPKIEnvelope, AES-128-CBC with RSAES-OAEP key transport, not the legacy RSAES-PKCS1-v1_5, so the CA must support OAEP), and signs that under the transaction attributes: the messageType (PKCSReq or RenewalReq), a caller-unique transactionId, and a 16-byte senderNonce that is generated when omitted. The messageData must be a well-formed PKCS#10 whose self-signature verifies under its own subject public key, or it is refused (scep/bad-input or scep/bad-popo) rather than enveloped into a message the CA would reject. The recipient CA certificate must assert the keyEncipherment key usage, since the EnvelopedData uses RSA key transport. A malformed spec, an unknown messageType, an over-long transactionId, or a senderNonce that is not 16 bytes is refused with a typed ScepError.
- pki.scep.parse(bytes, opts?) disassembles a SCEP pkiMessage. It verifies the outer SignedData signature first and refuses a message whose signature does not verify (scep/bad-signature), so the transaction attributes it returns are read only from a verified signer and are never surfaced alongside a false verdict. A valid signature proves only that the message is self-consistent with the certificate it embeds; pass opts.signerCert to authenticate a CA response against the CA certificate you hold, which refuses a signer whose public key does not match (scep/untrusted-signer) and reports signerAuthenticated. The verdict carries the messageType, transactionId, senderNonce, and, for a CertRep, the pkiStatus, failInfo, failInfoText, and recipientNonce, each mapped from its RFC 8894 enumerant and refused when unknown. Passing recipientKey ({ cert, key }) decrypts the pkcsPKIEnvelope to recover the messageData; a SUCCESS CertRep's payload is validated as a degenerate certs-only CMS SignedData and its issued certificate(s) and any CRL are surfaced in certificates and crls (a GetCRL response carries a CRL and no certificate), raw for the caller to path-validate. Passing expectedSenderNonce refuses a response whose recipientNonce does not echo the nonce that was sent. A message carrying more than one signer, a duplicate or multi-valued transaction attribute, or a missing mandatory attribute is refused.
- pki.errors.ScepError is the typed error for the SCEP codec, alongside the other per-domain PkiError subclasses.

## v0.6.1 — 2026-08-30

pki.ct verifies all of a certificate's SCTs against a trusted log-list and renders a certificate-level Certificate Transparency verdict, and pki.path.validate gains an optional CT gate.

### Added

- pki.ct.verifySctList(entry, list, logList, opts?) renders a certificate-level Certificate Transparency verdict (RFC 6962 sec. 3.3) over the set of SCTs a certificate carries, rather than one SCT at a time. It verifies each SCT against the trusted log-list through the same signature check pki.ct.verifySct applies, and reports how many distinct trusted logs verified an SCT (validScts, so a duplicated SCT cannot inflate the count), from how many distinct trusted log operators (operatorCount and operators), and whether that meets the CT policy. The policy is minScts and minOperators, both defaulting to the RFC floor of one valid SCT; the distinct-operator requirement is a browser CT policy layered on top of the RFC, so the caller sets the threshold and the verdict surfaces the counts. A policy shortfall is a verdict (policyOk: false), not an error, and a per-SCT trust or signature failure is recorded in its result row rather than sinking the verdict; only a mis-shaped entry, list, logList, or opts throws a typed CtError.
- pki.ct.x509CertEntry(cert, issuer) reconstructs the precertificate log entry from a final certificate that carries embedded SCTs (RFC 6962 sec. 3.2), the piece the embedded-SCT verification path needs end to end. It removes the signedCertificateTimestampList extension from the certificate's TBSCertificate by byte surgery, leaving every other byte of the CA-signed structure intact, and computes issuerKeyHash as SHA-256 of the issuer's SubjectPublicKeyInfo. The returned entry feeds pki.ct.verifySctList or pki.ct.reconstructSignedData directly.
- pki.path.validate accepts an optional Certificate Transparency gate: pass ctLogList (a pki.ct.parseLogList result) and ctPolicy ({ minScts, minOperators }) to verify the target certificate's embedded SCTs against the trusted log-list as part of path validation. The verdict carries a ct check on the target certificate's checks; a target that declares a CT policy but carries no SCT-list extension fails closed, and an SCT dated after the validation time (opts.time) is rejected rather than counted (RFC 6962 sec. 5.2, a client rejects a future-dated SCT). Callers that pass neither option are unaffected.

## v0.6.0 — 2026-08-30

The toolkit's public APIs graduate to stable, and pki.ocsp.verifyRequest verifies a signed OCSP request for responder implementers.

### Added

- pki.ocsp.verifyRequest(request, opts?) verifies a signed OCSP request (RFC 6960 sec. 4.1.1) for a responder implementer. It checks the requestor's signature over the exact tbsRequest under the public key of the requestor certificate embedded in the request, or supplied through opts.certs when the request carries none, using the same signature engine pki.ocsp.verify applies to a response. The verdict is { signed, signatureValid, signerCert, signerCerts, certs, signerSubject, requestorName, requestList, requestExtensions, version, reason }. Signing a request is optional under RFC 6960, so an unsigned request reports signed:false rather than an error, and signatureValid speaks only to the cryptographic check. Because the request's certificate field is unordered and a key may appear under an expired certificate beside its renewal, signerCerts lists every certificate whose key verified the signature, while certs is every parseable certificate the request carried, including intermediates that do not sign; the responder passes certs as the candidate pool to pki.path.build to discover and validate a trusted path to a signerCerts entry, confirms that certificate asserts digitalSignature keyUsage (RFC 5280 sec. 4.2.1.3, since it signed the request), then binds its subject to the identity expected, rather than depending on the position of the single signerCert.

### Changed

- The public APIs that previously carried an experimental status are now stable and covered by the stable-upgrade policy: a deprecation warning ships at least one minor release before any removal, and a minor release makes no silent breaking change. The graduation bar is a settled governing standard, a wire format proven correct, and a frozen public surface. Where a surface graduates without fully meeting that bar, the relaxation is named here. On interop: pki.tls certificate compression (RFC 8879), pki.ocsp.verifyRequest, and the CMC surface (pki.cmc and pki.schema.cmc, RFC 5272) have no independent implementation in the interop harness, so their own decoders are their only cross-check. On the shared network transport: the EST (pki.est), ACME (pki.acme), and networked CMP (pki.cmp) clients and pki.path.build's opt-in AIA fetching compose the shared node:https transport (pki.transport), whose fail-closed contract still gains requirements as each client composes it. On the governing standard: pki.schema.c509 tracks the draft-ietf-cose-cbor-encoded-cert Internet-Draft, Certificate Transparency tracks the Experimental RFC 6962 (the standardized CT v2 is RFC 9162), composite post-quantum signature support tracks the LAMPS composite-signature drafts, and Sigstore bundle verification tracks the evolving Sigstore bundle spec rather than a settled RFC. On surface stability: pki.lint ships a representative CA/Browser Forum Baseline Requirements subset that will gain rules over time, pki.webauthn.verifyAssertion's verdict shape is frozen as of this release and grows only additively, and pki.hpke wires the classical DHKEM modes with the post-quantum modes added later. In each case the public surface is stable, and any change a later standard revision, an added rule, or continued transport hardening requires is handled under the deprecation policy.

## v0.5.39 — 2026-08-29

pki.cmc.build and pki.cmp.build verify an embedded PKCS#10 request's proof-of-possession and refuse one whose self-signature does not verify.

### Added

- pki.cmc.build (`tcr` arm) and pki.cmp.build (`p10cr` arm) verify the embedded PKCS#10 request's proof-of-possession before signing or protecting the enrollment message: the request's self-signature must verify under the subject public key it carries (RFC 5272 sec. 6.3 for CMC; RFC 9810 sec. 5.3.3 for CMP, over the PKCS#10 structure of RFC 2986). A request whose signature does not verify is refused with a typed `cmc/bad-popo` or `cmp/bad-popo` error naming the offending request; a request with a valid proof-of-possession builds unchanged.

## v0.5.38 — 2026-08-29

Builder verbs reject a sparse or nullish array argument with a typed error instead of a native one.

### Changed

- The array arguments of pki.pkcs12.build (SafeContents bags), pki.ocsp.buildRequest and pki.ocsp.sign (the query and response batches), pki.cmc.build (requests and the CMS and other-message sequences), pki.crl.sign (revoked entries and the issuing-distribution-point and freshest-CRL general names), pki.crmf.build (controls and registration info), and pki.cms.encrypt (authenticated attributes) are checked for holes and nullish entries up front. A sparse or nullish array is now the verb's own typed `<domain>/bad-input` error naming the index, in place of the native `TypeError` the hole previously produced at the encoder. A valid (dense) array is unaffected and its emitted structure is byte-for-byte identical.

## v0.5.37 — 2026-08-29

pki.cms.decrypt can return the recovered content as an async iterable of plaintext chunks.

### Added

- `pki.cms.decrypt(input, keyMaterial, opts)` accepts `opts.stream: true`, returning the verdict's `content` as an async iterable of plaintext `Buffer` chunks instead of a single `Buffer`. It applies to EnvelopedData, AuthEnvelopedData, EncryptedData (the `{ cek }` and `{ password }` forms), and AuthenticatedData. The integrity-checked modes verify before the first chunk is yielded, so a forged message fails before any plaintext is exposed; the unauthenticated CBC modes stream the plaintext as the cipher produces it, so a large payload is never buffered whole. Every failure remains the single uniform `cms/decrypt-failed` verdict, on the streamed path as on the buffered one.

## v0.5.36 — 2026-08-29

pki.cms.encrypt accepts an async-iterable plaintext, encrypting a large payload without holding it whole in memory.

### Added

- `pki.cms.encrypt(content, recipients, opts)` accepts an async iterable of byte chunks as `content` (detected by `Symbol.asyncIterator`), alongside the existing `Buffer`, typed-array, `DataView`, and `ArrayBuffer` forms. It streams the plaintext through the AES-GCM or AES-CBC content cipher chunk by chunk, assembling only the ciphertext, so a large plaintext is not held in memory whole. The output is a byte-for-byte match for the buffered form and decrypts with `pki.cms.decrypt` and OpenSSL. This covers the recipient-based EnvelopedData and AuthEnvelopedData as well as the `{ cek }` and `{ password }` EncryptedData forms.

## v0.5.35 — 2026-08-29

pki.cmp.build now assembles the nested PKIMessage body an RA uses to forward or batch complete messages.

### Added

- `pki.cmp.build` accepts a `nested` body: `{ body: { nested: [pkiMessageDer, ...] } }` wraps an array of complete PKIMessage DER as a `NestedMessageContent` under the explicit `[20]` PKIBody tag (RFC 9810 sec. 5.1.3.5). This is the body a registration authority sends when it forwards or batches messages that were protected by other parties. Each entry is checked to parse as a PKIMessage and is then wrapped byte-for-byte unchanged, so a byte string that is not a PKIMessage is refused. An empty array is refused, because the field is `SIZE (1..MAX)`. Both failures raise `cmp/bad-input`. Following the same section, the inner messages are forwarded unchanged: each keeps its own protection, which the recipient validates, and `pki.cmp.build` does not re-sign, re-verify, or deeply inspect their contents.

### Fixed

- A caller array passed where a list of complete items is required is now refused with a typed error unless every position from 0 to its length is the array's own element. `pki.cms.sign` (the signer list) and `pki.cmp.build` (the `nested` message list) previously reached a native `TypeError` for a sparse array such as `new Array(2)`, or one carrying an empty slot or a `null` entry. An entry resolvable only through the array's prototype, including a polluted `Array.prototype` index, was worse: the entry deep-copy materialized it and the value was signed as though the caller had supplied it. The deep-copy now copies own array indices only, so a hole stays a hole, and a dense-array check refuses the list with `cms/bad-input` or `cmp/bad-input`, failing fast so a large sparse length cannot force a long traversal.
- A PEM-armored byte source passed to `pki.cmp.build` where DER is required is now refused with a typed error up front. Every field that takes a DER value the builder both validates with a parser and embeds verbatim is covered: the `nested` message list, the `p10cr` request, the signer certificate (`opts.cert`) and `opts.extraCerts`, and an embedded certificate or CRL. Because the parsers accept a PEM string, a PEM-armored `Buffer` (a file read straight from disk) passed validation but was embedded as ASCII armor, so the message was rejected only later, by its own parse, as `cmp/bad-der`, and for the signer certificate only after the private-key operation. The builder now requires a DER SEQUENCE for these fields, so a PEM or non-DER input fails immediately with a clear code and the bytes checked are the bytes embedded.

## v0.5.34 — 2026-08-29

A subjectAltName URI shorthand whose authority is a bracketed IPv6 literal is now accepted rather than refused.

### Fixed

- A bare-string `subjectAltName` entry whose value is a URI with a bracketed IPv6 authority, such as `https://[2001:db8::1]:443/path`, now classifies as a `uniformResourceIdentifier`. The bracketed host is taken as one unit before an optional port, so a colon inside the IPv6 literal is no longer read as the port separator. An unterminated bracket, a bracket body that is not a valid IPv6 address, or bytes other than a port after the closing bracket stay refused, and the explicit `{ uniformResourceIdentifier: ... }` object form is unchanged.

## v0.5.33 — 2026-08-29

pki.cms.sign and pki.cms.verify accept the content as an async iterable of byte chunks, so a detached signature over a large payload is produced and verified without holding the payload in memory.

### Added

- `pki.cms.sign` accepts its `content` as an async iterable of byte chunks (for example an async generator), signing a large payload without holding it in memory. This form requires `detached: true` and signed attributes: the payload is hashed incrementally to build the message-digest attribute (RFC 5652 sec. 5.4), in a single pass that serves every signer, so signers may use different digest algorithms. The signature covers the same content as the buffered form.
- `pki.cms.verify` accepts its `content` option as an async iterable of byte chunks, verifying a detached signature over a streamed payload. The stream is hashed once for every signer, so every signer must carry signed attributes; a signer that signs the content directly is refused with a typed error and needs the content as a `Buffer`.

## v0.5.32 — 2026-08-28

The parse verbs accept their DER input as any BufferSource: an ArrayBuffer, a DataView, or any typed array, not only a Buffer or a Uint8Array.

### Added

- Every parse verb accepts any `BufferSource`, not only a `Buffer` or a `Uint8Array`: `pki.x509.parse`, `pki.crl.parse`, `pki.csr.parse`, `pki.pkcs8.parse`, `pki.cms.parse`, `pki.pkcs12.parse`, `pki.ocsp.parse` and `parseRequest`, `pki.cmp.parse`, and `pki.schema.cmc.parse` (including `parsePkiData` and `parsePkiResponse`, where a `DataView` is now read correctly rather than coerced to an empty buffer). An `ArrayBuffer` or a `DataView` produces the same result as the equivalent `Buffer`.
- Many byte-valued options on the signing, verifying, and enrollment verbs were widened to accept any `BufferSource` as well. These include the certificate and DER inputs to `pki.cms.sign` and `pki.cms.verify`; the `messageImprint` and TSA certificate in `pki.tsp.sign`; the `requestorName` and nonce in `pki.ocsp`, and the response in `pki.path.verifyOcspResponse`; the `expectedSender` and signer certificate in `pki.cmp`; a signer's `keyIdentifier` and `spki` in `pki.cmc`; the certificate and CSR inputs to `pki.acme` (`finalize`, `revokeCert`, `ariCertId`, `renewalInfo`); the CSR and `challengePasswordFromTlsUnique` channel binding in `pki.est`; the issuer SPKI in `pki.crl.verify` and the byte serial in `pki.crl.isRevoked`; a raw subject Name, a `subjectKeyIdentifier` or `authorityKeyIdentifier`, and a byte serial number in `pki.x509.sign` and `pki.csr.sign`; and an `iPAddress` name-constraint base in `pki.path.validate`.
- `pki.oid.isDottedDecimal(s)` reports whether a string is a dotted-decimal object identifier: two or more numeric arcs separated by dots.
- `pki.asn1.isPrintableString(s)` reports whether a string contains only the characters an ASN.1 PrintableString may carry: `A` to `Z`, `a` to `z`, `0` to `9`, space, and the symbols `'()+,-./:=?`.

### Changed

- A private key, a password, and other secret byte inputs keep their existing contract of a `Buffer`, a `Uint8Array`, a PEM string, or a `CryptoKey` where one is accepted. A secret input still refuses an `ArrayBuffer` with a typed error, because widening the secret ownership paths is a separate decision.

## v0.5.31 — 2026-08-24

The signing verbs accept a WebCrypto CryptoKey as the signing key, and a subjectAltName entry may be a bare string classified into its GeneralName form.

### Added

- Every signing verb -- `pki.x509.sign`, `pki.csr.sign`, `pki.crl.sign`, `pki.cms.sign`, `pki.ocsp.sign`, `pki.attrcert.sign`, `pki.tsp.sign`, and `pki.crmf.build` -- accepts a WebCrypto `CryptoKey` as its signing key, so a key from `pki.key.generate` (or `pki.webcrypto.subtle`) signs directly without first being exported to PKCS#8. A PKCS#8 private key as DER (a `Buffer` or `Uint8Array`) or PEM (a string) continues to work exactly as before, with the signature algorithm resolved from the key's own SubjectPublicKeyInfo. A `CryptoKey`'s own algorithm must be compatible with that resolved scheme, because WebCrypto binds a key to one algorithm: an RSASSA-PSS `CryptoKey` signs RSASSA-PSS, so pass `opts.pss` for it, whereas a raw PKCS#8 RSA key defaults to RSASSA-PKCS1-v1_5.
- A `subjectAltName` (and any other `GeneralName`) entry may be a bare string, classified fail-closed into its form: a hostname such as `"host.example.com"` (including a `*.` wildcard or an underscore label) becomes a `dNSName`, `"user@example.com"` an `rfc822Name`, an IPv4 or IPv6 literal such as `"192.0.2.1"` an `iPAddress`, and a `"https://host.example/path"` URL a `uniformResourceIdentifier`. Shorthand and object entries interoperate in the same array. A string that does not unambiguously match one form -- a host:port, an opaque `urn:`/`mailto:` URI, or an empty string -- is refused with a typed `bad-input` error rather than guessed; the explicit object form (`{ dNSName: "..." }`) still accepts any value, and a pre-encoded Extension DER passed through the escape-hatch array form is unaffected.

### Changed

- A signing key that is a public or secret `CryptoKey`, or a `node:crypto` KeyObject rather than a WebCrypto `CryptoKey`, is now refused with a message that names the specific problem -- the wrong key type, or a KeyObject that should be passed as a `CryptoKey` or exported to PKCS#8 -- instead of the generic "must be a CryptoKey or PKCS#8" message. The `"a signing key is required"` errors on `pki.x509.sign`, `pki.crl.sign`, and `pki.attrcert.sign` now name the `CryptoKey` option alongside PKCS#8.

## v0.5.30 — 2026-08-24

A CMP certReqTemplate keySpec that names an ISO/IEC 9796-2 RSA signature scheme is now refused, instead of being surfaced to the caller as a non-RSA algorithm requirement.

### Security

- `pki.cmp.session` refuses a certReqTemplate keySpec whose `id-regCtrl-algId` names an ISO/IEC 9796-2 RSA signature-with-message-recovery scheme, with `cmp/bad-info-value`, rather than surfacing it to the caller as a non-RSA algorithm requirement. RFC 9483 sec. 4.3.3 reserves an RSA key requirement for `id-regCtrl-rsaKeyLen`; the 9796-2 schemes are RSA, so a keySpec naming one is now rejected the same way an rsaEncryption or RSASSA-PSS algId already was. The classifier recognizes the deterministic (1.3.36.3.4.2) and randomized (1.3.36.3.4.3) sub-arcs by prefix -- so a hash variant registered later is caught without being listed -- and ISO/IEC 9796-1 (1.3.36.3.4.1) on the same registrant arc. The generic signatureScheme parent (1.3.36.3.4) and the sibling authentication arc (1.3.36.3.5, whose children include ECC) are not treated as RSA, so a non-RSA algorithm under either is still surfaced. Recognizing these OIDs classifies a keySpec requirement; it is not a claim that the toolkit produces or verifies a 9796-2 signature.

## v0.5.29 — 2026-08-24

pki.path.validate refuses a mis-shaped trust anchor instead of returning a verdict against it, and accepts a parsed certificate directly.

### Added

- `pki.path.anchorFromCert(cert)` turns a parsed certificate into the `{ name, publicKey, algorithm }` trust-anchor tuple `pki.path.validate` and `pki.path.build` consume, so a root can be pinned from its certificate without hand-building the tuple. `pki.path.validate` and `pki.path.build` also accept a parsed certificate passed directly as the anchor.

### Changed

- A normalized trust anchor -- what `pki.path.anchorFromCert` returns and what `pki.path.build` reports as `result.trustAnchor` -- carries a defined set of fields: `name`, `publicKey`, `algorithm`, and `parameters`, plus `purposes`, `distrustAfter`, `subjectDer`, `label`, and `mozillaCaPolicy` when the source supplies them (the fields `pki.trust.parseCertdata` emits). These survive normalization, so a pinned trust-store entry round-trips; a field attached outside that set is not carried onto the anchor.
- A trust anchor's `purposes` and `distrustAfter` constraint maps must be plain own data properties. A map -- or one of its entries -- supplied as a getter, or reached through the object's prototype rather than as an own property, is refused with `path/bad-input` rather than read, so a getter cannot answer a purpose or distrust check inconsistently and a restriction is never silently dropped. The `{ purposes, distrustAfter }` shape `pki.trust.parseCertdata` emits and a hand-built one are the normal, unaffected form.
- A trust-anchor tuple's nested `algorithm.oid` and `name.rdns` must likewise be plain own data properties. An accessor-backed or prototype-inherited definition is refused with `path/bad-input` rather than read, so a getter on one nested field cannot rewrite the other -- for example, rewriting a wrong declared algorithm OID to the key's real one -- before it is validated. A plain `{ oid }` algorithm and `{ rdns, bytes }` name, and a parsed certificate's own, are the normal, unaffected form.
- The ACME client's per-request methods refuse an unrecognized option instead of reading it as absent and applying a default: `finalize`, `pollOrder` / `pollAuthorization`, `downloadCertificate`, `revokeCert`, `keyChange`, and `renewalWindow`. A mistyped option name is now an `acme/bad-input` error rather than a silently ignored setting, matching the client constructor and the rest of the toolkit's option-taking verbs.

### Security

- `pki.path.validate` refuses a malformed `opts.trustAnchor` with `path/bad-input` at entry, rather than seeding the path from it and returning a soft verdict. An anchor tuple missing its `algorithm` could previously make the path validate and return `valid: true` -- a self-describing key algorithm filled the gap the absent field left -- so a caller who passed a mis-shaped anchor received a verdict that did not answer the question they asked. The anchor is now normalized and shape-checked at the door, the same way `pki.path.build` already treated its `trustAnchors`.
- `pki.path.validate` and `pki.path.build` also refuse a trust anchor whose declared `algorithm` does not match the algorithm of its `publicKey`, and take the key's algorithm parameters from that SubjectPublicKeyInfo rather than a declared `parameters` field. An anchor that named a different or unrelated algorithm than the key it carried was previously accepted and validated against the real key; a declared algorithm inconsistent with the key is now a `path/bad-input` refusal at entry. And because the key's own parameters are authoritative, a declared curve that disagreed with the key can no longer be promoted and inherited by an intermediate certificate that omits its own parameters -- which could otherwise validate a chain RFC 5280 parameter inheritance from the real key should reject.
- A trust anchor passed as a parsed certificate is recognized as a certificate before any tuple field is read, so a value reached through the object's prototype -- such as a polluted `Object.prototype` supplying `name`, `publicKey`, and `algorithm` -- cannot reclassify the certificate as a hand-built tuple and bind a substituted key. The certificate's own key is always the one used.
- A trust anchor supplied as a `Proxy`, or one whose `purposes` / `distrustAfter` constraint map is a `Proxy`, is refused with `path/bad-input`. A `Proxy`'s traps can answer a field read differently on successive lookups or report a field absent while forwarding the rest, so no field-by-field normalization can trust it to describe itself -- a `Proxy` could report `purposes` absent while carrying the other fields, or a `Proxy` distrust map could report no keys, dropping a `{ serverAuth: false }` restriction or an expired-cutoff date the caller attached and validating a path the anchor forbids. A normal anchor -- a plain tuple, a parsed certificate, or an object inheriting from one, with plain-object constraint maps -- is not a `Proxy` and is unaffected.

## v0.5.28 — 2026-08-22

Importing the toolkit is now silent, and a key's WebCrypto algorithm can no longer change under a signature once the key has been created.

### Changed

- `require("@blamejs/pki")` no longer prints Node experimental-feature warnings on load. The engine's typed-array scan reads each global's property descriptor and uses only a data value, so it never touches a host's lazy accessor (Node's `localStorage` and `WASI` emit an `ExperimentalWarning` the moment they are read). Recognition of the concrete typed-array kinds -- the reason for the scan -- is unchanged, since those are ordinary data properties.

### Security

- A `CryptoKey`'s `algorithm` is immutable once the key is created: the property is non-writable so it cannot be replaced, and its value is frozen so its fields cannot be changed. This engine reads `key.algorithm.hash` at sign time, and a mutable algorithm let the hash checked against a JWS `alg` (an `RS256` header signs under SHA-256) be rewritten between that check and the signature -- by swapping the whole object or a field of it, including from a microtask during the signing await -- producing a JWS whose signature does not match the algorithm its header advertises. The frozen value is a copy, so a caller's own `importKey` parameters object is left untouched. A key adopted from another WebCrypto implementation is re-imported from its own algorithm; the keys this engine mints, which is what the enrollment builders sign with, carry the immutable one.

## v0.5.27 — 2026-08-22

A mistyped option passed to pki.trust.anchor or the pki.acme.client constructor is now refused, naming it, instead of being read as absent and silently defaulted.

### Changed

- `pki.trust.anchor(entry, opts)` rejects an option it does not recognize, naming it, instead of ignoring it and applying the default. The one option it reads is `purpose`.
- The `pki.acme.client(directoryUrl, opts)` constructor rejects an unrecognized option the same way. The options it reads are `accountKey`, `accountJwk`, `alg`, `transport`, `tls`, `timeout`, `maxResponseBytes`, `maxRedirects`, `maxNonceRetries`, `maxPolls`, `maxTotalWait`, `sleep`, and `clock`; each method the client returns validates its own per-call options separately.

### Security

- An unrecognized option is a fail-closed error rather than a silent default. The prior behavior meant a security-relevant option -- a shorter redirect budget, a specific trust purpose -- that was misspelled took no effect and raised no error, so a caller could believe a stricter setting was in force when the default was.

## v0.5.26 — 2026-08-22

Revoking a certificate and asking a certification authority what it offers now go through the same verified CMP transaction as enrollment.

### Added

- `session.revoke(request)` drives the RFC 9483 sec. 4.2 revocation exchange. The request names the certificate as `{ certificate }` or as `{ certDetails: { issuer, serialNumber } }`, with an optional `reason` taking a CRLReason name. It returns a terminal verdict of `revoked`, `rejected`, or `poll-timeout`, carrying the responder's `PKIStatusInfo` and any `CertId` values and CRLs the response supplied.
- `session.info(request)` drives the four RFC 9483 sec. 4.3 support messages, one per call. `{ caCerts: true }` asks for the certification authority certificates available for chain construction. `{ rootCaCert: <cert> }` asks for a root key update and reads the `RootCaKeyUpdateContent` reply. `{ certReqTemplate: true }` asks for the requirements a future certificate request should meet, returning the template and any `keySpec` constraints. `{ crlUpdate: { issuer, dpn?, thisUpdate? } }` asks for a CRL from a named source. The verdict is `answered`, `rejected`, or `poll-timeout`; `answered` reports `present` alongside `value`, since an absent response value is how each of the four says nothing is available.
- `pki.cmp.build` accepts a structured `crlEntryDetails` on an `rr` body: `{ reason: 'keyCompromise' }` encodes the reasonCode extension the profile requires. A pre-encoded `Extensions` DER is still accepted for an entry extension outside that shape.
- The `id-regCtrl-algId`, `id-regCtrl-rsaKeyLen`, and `id-regCtrl-altCertTemplate` object identifiers RFC 9480 sec. 2.16 adds are in the registry, so a `keySpec` control resolves to a name.

### Changed

- Delayed delivery is recognized for a revocation and a support message. RFC 9483 sec. 4.4 puts the `waiting` status in an `ip`, `cp`, or `kup` when answering an enrollment and in an error message when answering anything else, so an error body carrying `waiting` now drives the bounded poll loop for those two operations, with the `pollReq` referring to the whole message. An error message that is not delayed delivery must state the rejection status: an error naming `accepted`, `grantedWithMods`, or another non-rejection status, or a `waiting` carrying `failInfo`, is refused as malformed rather than surfaced as a trusted rejection verdict its own `PKIStatusInfo` contradicts. An enrollment has no delayed-delivery error at all — the profile places enrollment `waiting` in an `ip`, `cp`, or `kup` — so a `waiting` error answering an enrollment is refused, not read as a rejection.
- One transaction per session covers all three verbs. A session that has revoked will not then enroll, because both would run under the same transactionID and nonce chain.

### Security

- A session revokes its own certificate. The signature over an `rr` is the proof of authorization to revoke (RFC 9483 sec. 4.2), so the certificate named in the request must be the one the session protects its messages with, compared by serial number and by the RFC 5280 sec. 7.1 canonical distinguished-name rule. A PBMAC1 session is refused outright: a shared secret establishes a bootstrapping relationship and says nothing about which certificate the holder may revoke. Revocation on behalf of another entity is a registration authority operation and is driven with `pki.cmp.build` and `pki.cmp.transfer`.
- The reasonCode is always sent, at `unspecified(0)` when no reason is given. RFC 9483 sec. 4.2 makes `crlEntryDetails` required and says the code must be 0 when the reason is unknown or is not to be published. This is the opposite of the RFC 5280 sec. 5.3.1 rule for a CRL entry, where absence and `unspecified` carry the same meaning and the extension is omitted, so the CRL behavior is not reused here.
- A response is held to the shape its operation defines before its content is read. An `rp` must carry exactly one status, and an accepted one must not also carry `failInfo`. When an accepted `rp` names the certificates it revoked in `revCerts`, that entry is bound to the certificate the request named: exactly one entry, its issuer and serialNumber equal to the revoked certificate's under the RFC 5280 sec. 7.1 canonical rule, so a verified `revoked` verdict cannot report an unrelated certificate as revoked. A `genp` must carry exactly one `InfoTypeAndValue`, whose infoType must be the one that operation is answered with: a root key update is requested with `id-it-rootCaCert` and answered with `id-it-rootCaKeyUpdate`, so a response echoing the request identifier is a different operation's answer and is refused.
- A `rootCaKeyUpdate` response must carry `newWithOld`, and the three certificates must stand in the relationships that make a root key update work. RFC 9480 marks the field OPTIONAL in the syntax and RFC 9483 sec. 4.3.2 requires it of a response, for the reason it states: an entity that trusts the old root needs that certificate to gain trust in the new one. That is a claim about signatures and keys, not about the fields being present, so `newWithOld` is checked to carry the new root key, to name the same subject as `newWithNew`, and to be issued and signed by the old root named in the request, and `oldWithNew`, when sent, to carry the old root key, name the old root, and be issued and signed by the new one. The names matter as much as the keys: a certification authority that has ever issued an ordinary certificate for the new key satisfies key equality and signature validity on its own, and its holder could pair it with a self-signed certificate of their choosing and have the result read as the authority's rollover. Names are compared under the RFC 5280 sec. 7.1 canonical rule, so a re-encoded but equal name still matches. Each of the three must also carry the authority the update transfers — `basicConstraints` with `cA` TRUE, and a `keyUsage`, where present, that allows `keyCertSign` — since an ordinary end-entity certificate for the same subject and key satisfies names, key and signature while being able to certify nothing. `newWithNew` is checked under its own key when it is self-issued, which is the case for a root; sec. 4.3.2 also extends this operation to a directly trusted non-root certificate, whose issuer the message does not carry, and there its own signature is left unchecked rather than the update refused for a check that cannot be run. Three certificates that merely parse establish neither direction of the transition. The signatures go through the same certification-path engine that verifies a message's protection, so the EdDSA low-order-point and algorithm-confusion gates apply here too, and a signature that is not octet-aligned (a BIT STRING declaring unused bits) is refused before the engine, the same shape the path verifier rejects. The certificate the request names as the current root is itself held to being a CA — refused at the door, before the one-shot transaction engages — since the response's rollover signatures are verified against its key, and an end-entity certificate there would let a cross-certificate read as a rollover.
- A `certReqTemplate` response must omit `publicKey`, `serialNumber`, `signingAlg`, `issuerUID`, and `subjectUID` from its template (RFC 9483 sec. 4.3.3). A template stating a public key would direct an entity to request a certificate over a key the responder chose, which is what the `keySpec` field exists to avoid. A `keySpec` control must be `id-regCtrl-algId` carrying a non-RSA AlgorithmIdentifier or `id-regCtrl-rsaKeyLen` carrying a positive integer. "Other than RSA" is decided by OID family. Every object identifier under an RSA-dedicated arc — the PKCS#1 arc, the TeleTrusT rsaSignature arc, or the BSI TR-03110 id-TA-RSA arc (EAC Terminal Authentication) — is an RSA algorithm, save the PKCS#1 arc's two auxiliary parameters (`mgf1` and `pSpecified`, the mask-generation and OAEP-label identifiers), which are not RSA algorithms and are surfaced, so a standardized member this toolkit has not separately named — `sha1WithRSAEncryption`, the `md*` and `sha224` variants — is refused with the ones it has; the RSA identifiers on arcs it shares with non-RSA algorithms — `id-rsa-kem`, `id-kem-rsa`, the RSASSA-PKCS1-v1_5-with-SHA-3 set, RSASSA-PSS-with-SHAKE, every legacy OIW RSA identifier on the arc it shares with DES, DSA, and the hashes, the X.500 directory RSA OIDs (the `rsa` public-key identifier and the signatureAlgorithm sub-arc's RSA members), and the Chinese GM/T `sm3WithRSAEncryption` — are named explicitly, since no prefix can isolate RSA there. Each arc is read from the registry rather than written as a literal, so `pki.oid.register` cannot move it underneath the check. The composite ML-DSA + RSA signatures are deliberately not refused: a hybrid is a composite key rather than an RSA one, and `rsaKeyLen` cannot state it either. That is the only rule the control is held to: an algorithm the registry cannot name is surfaced rather than refused, since a `keySpec` carries one entry per algorithm the CA supports and the entity picks one it can generate, so an unrecognized offer is passed to the caller with a null name rather than failing the whole exchange and dropping the algorithms alongside it.
- A CRL answer is bound to the query that asked for it. RFC 9483 sec. 4.3.4 does not say a responder returns a CRL; it returns the latest one from the referenced source, and only when it is more recent than a `thisUpdate` the request supplied, with the response value absent in every other case. A CRL from another issuer, or one no newer than the copy the caller already holds, answers a different question, so it is refused rather than reported as `answered`. The issuer is compared under the RFC 5280 sec. 7.1 canonical rule. A request that names a distribution point is bound to that point wherever the CRL states one: RFC 5280 sec. 5.2.5 puts the scope in `issuingDistributionPoint`, and sec. 4.3.4's own note names that extension as a place a distribution point name is obtained from. The test is the one RFC 5280 sec. 6.3.3 applies to a shard CRL, at least one name in common compared as identical encodings, which sec. 5.2.5 requires of the two fields; a canonical comparison would accept a CRL published for a point the request never named. A CRL stating no scope is claiming to be its issuer's complete list, which sec. 5.2.5 permits and which answers a request for any point of that issuer, so the distribution point cannot bind that case. The issuer is required for it: a request naming a `dpn` must name an `issuer` as well, and the two are used differently. `CRLSource` is a CHOICE, so the message carries the distribution point (sec. 4.3.4 sends that alternative when a distribution point name is available), while the issuer states which CA's CRL the caller will accept. A `dpn` alone is refused rather than answered with a CRL from a CA nobody named; sec. 4.3.4's own note says a distribution point name is obtained from a certificate's `cRLDistributionPoints` or from a held CRL's `issuingDistributionPoint`, and both carry the issuer alongside it. An unbound request is still available through `pki.cmp.build` and `pki.cmp.transfer`.

### Notes

- A `crlUpdate` request carries one `CRLSource` alternative, since it is a CHOICE: the `dpn` when a distribution point name is given, the `issuer` otherwise. The `dpn` arm takes `fullName`; the `nameRelativeToCRLIssuer` alternative is not built, which is the line `pki.crl.sign` already draws for `issuingDistributionPoint` and `freshestCRL`.
- The registration authority side of these operations is unchanged: `krr` and `ccr` requests and the `nested` body remain unbuildable, and a session has no way to resume a poll across a process restart.

## v0.5.25 — 2026-08-21

A key that cannot sign can now prove possession, so an ML-KEM certificate request has a proof to carry instead of no option at all.

### Added

- `pki.crmf.build` emits a `POPOPrivKey` proof of possession under `pop.type` of `keyEncipherment` or `keyAgreement`. `pop.method: 'subsequentMessage'` with `pop.subsequentMessage` of `encrCert` or `challengeResp` declares which follow-up exchange completes the proof (RFC 9810 sec. 5.2.8.3.2 and sec. 5.2.8.3.3); no key material leaves the requester and every key type can produce it. `pop.method: 'encryptedKey'` encloses the requester's private key for the certification authority in a CMS `EnvelopedData` whose content type is `id-ct-encKeyWithID`, taking `pop.privateKey`, `pop.recipients`, `pop.identifier`, and `pop.archive: true`. `pki.cmp.build` carries either in an `ir`, `cr`, or `kur` body.
- The requested version follows what the message carries: a CMP request whose proof of possession uses `encryptedKey` or `agreeMAC` announces cmp2021(3), which RFC 9810 sec. 5.2.8.3 requires. Before this a request carrying an `encryptedKey` proof went out announcing cmp2000(2), and this toolkit's own reader refused the message it had just built.

### Changed

- `spec.pop` refuses a field it does not recognize. Each rule below is one a caller turns off by naming it, so a misspelled key must not read as an omitted one: `archve: true` would have withheld the archival consent while appearing to give it.

### Security

- An `encryptedKey` proof must enclose the private half of `certTemplate.publicKey`. RFC 4211 sec. 4.2 defines the field as "the encrypted private key matching the public key for which the certificate is to be issued"; enclosing any other key proves possession of something the request never asked to have certified, while every structural check still passes. The public key is derived from the supplied private key through the toolkit's own key engine and compared before the message is built.
- An `encryptedKey` proof requires `pop.identifier`. The ASN.1 marks `EncKeyWithID.identifier` OPTIONAL and RFC 4211 sec. 4.2.1 then makes it mandatory whenever the purpose is proving possession, for a reason the section states: without it a decrypting agent holds a key it cannot attribute, so an intercepted key can be wrapped in someone else's request and recovered.
- The two alternatives RFC 4211 sec. 4.2 deprecates as it defines them, `thisMessage` and `dhMAC`, are refused with their successors named. `pki.schema.crmf.parse` still reads both, since a peer may send one.
- A `keyEncipherment` proof cannot carry a MAC alternative. RFC 4211 sec. 4.2 lists three methods for an encipherment key and introduces the MAC alternatives only in sec. 4.3, "for keyAgreement (only)". The parser already refused such a message; the builder no longer produces one.

### Notes

- The `agreeMAC` proof is not built. It requires the RFC 2875 static Diffie-Hellman shared secret between the requester's key and a certification authority certificate the requester already holds, a classical key-agreement primitive this toolkit does not otherwise carry. `pki.crmf.verifyPop` continues to report an inbound `agreeMAC` as unverified, naming the arm. Use `subsequentMessage`, which any key type can produce.

## v0.5.24 — 2026-08-21

An ACME certificate download is now bound to the order that asked for it, so a certificate for another key or another name is refused instead of returned as the issued one.

### Changed

- `downloadCertificate` requires the material that makes that check possible: `expectedSpki`, `identifiers`, or both. A call supplying neither is refused with `acme/binding-required` rather than returning a certificate nothing looked at. Passing `requireBinding: false` waives the requirement to supply material and never the check on material that is supplied, and the result reports `boundToKey` and `boundToIdentifiers` so an unchecked download cannot read as a checked one. See MIGRATING.md.

### Fixed

- `downloadCertificate` checks the end-entity certificate it received against the order: its subject public key must be the one this order's CSR asked to have certified (`acme/certificate-key-mismatch`), and its identifier set must equal the order's identifiers (`acme/certificate-identifier-mismatch`). A certificate's identifiers are its dNSName and iPAddress subject alternative names, with its subject common name read only where it asserts none: where an alternative name is present the common name is not an additional identity, and an address in a common name is never an IP identity, because name matching reads the alternative names and does not fall back. The binding runs on whichever chain is returned, including a chain chosen through `selectChain`.
- An identifier that maps to no certificate name is refused as `acme/unsupported-identifier-type` rather than dropped from the comparison, on both sides of it. The ACME identifier registry is open and only `dns` and `ip` name something a certificate carries, so an order identifier of another type, a certificate `subjectAltName` that is neither a dNSName nor an iPAddress, and a subject common name that is neither a dns name nor a canonical IP address, would otherwise be skipped while the comparison still reported the whole set as checked: an order for a name plus one other identifier was satisfied by a certificate covering only the name, a certificate additionally naming a mailbox compared equal to an order that covered no mailbox, and a certificate naming both the order's name and a trailing-dot spelling of another compared equal on the strength of the first. The outbound `finalize` check refuses the same names, and reads every common name the request carries whether or not it also asserts alternative names -- a request naming the order's identifier in an alternative name and an unauthorized one in its subject is a request for a name the order does not cover, since a CA may carry that common name through into the certificate it issues.
- Names fold with ASCII case rules rather than the Unicode mapping, so a character whose Unicode lowercase is ASCII -- U+212A KELVIN SIGN folds to `k` -- is not read as the ASCII name it would fold to. That fold now has one definition the host-part rule, the CMP domain comparison and this one share.
- The names a certificate carries survive a replaced built-in. Every operation the shared PKIX decoders traverse, convert, copy and compare names with is bound when the module loads, and the tables that decide which GeneralName alternative a tag selects, which string types are DisplayText, and which decoder an extension OID resolves to hold no prototype. Replacing `Array.prototype.map`, `Buffer.prototype.toString`, `Buffer.concat`, `Array.prototype.push` or `Array.prototype.forEach` after load, or planting a name on `Object.prototype`, could otherwise present a subject alternative name or a subject common name the encoded certificate does not carry -- which any comparison downstream, including the certificate binding above, would then answer about.
- Every guard module freezes its exports. A boundary reaches its fail-closed check as a property of the guard object at the moment of the call, and the module registry hands every caller the same object, so a single assignment would have replaced a check -- a constant-time comparison, a size cap, a secret wipe -- in every module at once.

## v0.5.23 — 2026-08-20

The tables that decide which status codes, revocation reasons, trust bits and extensions this toolkit recognizes now answer from an operation taken at load, and an unsupported HTTP Digest algorithm is refused rather than read off a prototype.

### Changed

- Eighteen further modules -- ACME, EST, CMC, WebAuthn and its metadata reader, Certificate Transparency, trust-store ingest, TLS certificate compression, HPKE, HTTP Digest, the CRL and attribute-certificate signers, and the OCSP, CRL, attribute-certificate and shared PKIX schemas -- are held to the live-read rule, each declaring the reads it still carries as a count that can only fall.

### Fixed

- An HTTP Digest challenge naming an unsupported algorithm is refused with a typed error. The algorithm registry was an ordinary object, so a name matching any member of `Object.prototype` answered the supported-algorithm gate with a value the registry never held: the refusal was skipped and the call ended in an untyped `TypeError`. The registry now carries a null prototype.
- OCSP response statuses and revocation reasons, CRL reason codes, CCADB trust bits, attribute-certificate critical extensions and object-digest types, Certificate Transparency log states, and the repeated-parameter check on an HTTP Digest challenge all decide membership through a captured operation, so replacing the runtime's own membership test after load cannot widen what they accept.

## v0.5.22 — 2026-08-20

The list tests that decide whether a caller's argument is refused, and which form an extension spec is in, now answer from operations taken at load rather than read when they run.

### Changed

- The DER codec, the PKIX builders and the certificate signer are held to the live-read rule, with the reads each still carries declared as a count that can only fall. Certification-path validation's declared count falls in this release as its list doors convert.

### Fixed

- The DER builder refuses a non-list of children under a captured test. Every structure this toolkit encodes passes through that door, and it was the busiest live read in the library by two orders of magnitude.
- `pki.x509.sign` picks which form the caller's extension spec is in with a captured test. That choice decides which fields are read and therefore what is signed into the certificate: answering wrongly sends an object down the list arm, and the extensions it carries are never seen. The same test decides whether the spec asserts keyCertSign, which is what makes the issued certificate a CA.
- The name, key-usage and GeneralNames builders refuse a non-list argument under a captured test, as do certification-path validation's own list doors.

## v0.5.21 — 2026-08-20

The check that holds the crypto engine to load-time captures could be satisfied around, so nine modules had taken the safe primitive at one site and were never held to it anywhere else.

### Added

- `guard.intrinsic.bufferEquals`, the captured byte-identity comparison the bindings above are decided with.

### Changed

- Taking the captures has one spelling again. The guard orchestrator no longer re-exports them, so a module reaches them by importing the module that holds them, and the check reads that off the loaded module graph rather than off the text. This is the enforcement change: a module that adopts one safe primitive is held to the rule everywhere, and no way of writing the import, or of writing something that resembles one, changes the answer.
- The seven modules the widened check surfaced carry a declared count of remaining reads rather than an exemption. A new live read pushes a module past its figure and fails, and converting reads without lowering the figure fails too, so the number keeps naming the real count. A module reaching zero leaves the list and is held to zero.

### Fixed

- An OCSP response is bound to the certificate it answers for with captured byte comparisons. The CertID says the response concerns this issuer and the responder ID says this key signed it, and both were decided by a `Buffer.prototype.equals` read at call time: replaced after load it reports every hash equal, and a `good` signed by a different CA answers for the certificate under check.
- The signer's key is matched to its certificate under a captured case fold. WebCrypto algorithm names compare case-insensitively, so the check folds both sides; dispatched live, a replaced fold reported two different algorithm names equal and a key whose algorithm does not match the certificate passed the gate that exists to catch exactly that.
- `pki.sign` decides the RSASSA-PSS parameters, the digest tables and its key-shape tests on captured operations, so a caller who replaces one after this package loads cannot change which algorithm a signature runs under.
- A signing key is classified by asking the value what it is rather than by `instanceof` against a global. The old test read the `Uint8Array` binding at call time, and it answered wrongly in both directions on its own terms: a real typed array from another realm was not one, and an object built on the prototype was.

## v0.5.20 — 2026-08-20

Five verdicts that turned on list membership now decide it by comparison, so replacing an array method after the module loads cannot change what a certificate, a responder or a signed message is found to be.

### Added

- `guard-list`, an internal choke point for membership decided by comparison. Four verbs cover the rule shapes a verdict needs: is this value present, are all of these present, does any member satisfy a test, do all of them. An absent list is honestly empty rather than a throw, because these run on verdict paths where a throw would read as a different verdict. It is not on the public namespace; the surface is the verdicts above.

### Changed

- Certification-path building asks its loop-detection and fetch-dedupe sets through captured methods. These bound the work a hostile chain can cause, and a replaced `Set.prototype.has` answering false let a cycle be walked and a URL be fetched repeatedly until a size cap stopped it.

### Fixed

- `pki.path.validate` holds its `requiredEku` gate against a replaced `Array.prototype.indexOf`. The purpose test IS the decision about what the certificate may be used for, and dispatched live it reported `serverAuth` present on a leaf whose extended key usage carried only `emailProtection`, returning a valid chain for a certificate the caller had asked it to refuse. Certificate-policy membership and the `anyPolicy` scans in the policy tree are decided the same way.
- `pki.cms.verify` keeps `trusted: false` for a message no supplied anchor covers. The message-level verdict combined the per-signer answers with `every`, and a replaced one reported the whole set trusted without consulting a single signer.
- An OCSP response is still refused when its delegate lacks id-kp-OCSPSigning. Responder authorization is the decision about who may answer for an issuer, and reading the purpose list through the prototype let a delegate the CA never authorized speak for the whole issuer.
- A TPM attestation certificate still needs the tcg-kp-AIKCertificate purpose. That test is what makes a leaf an attestation key, so reading it live let an ordinary certificate be accepted as one.
- A timestamp token carrying an unrecognized critical extension is still refused (RFC 3161 sec. 2.4.2). The scan for a critical extension IS the gate, and a replaced `Array.prototype.some` answering false made the extension invisible and the unusable token acceptable.
- `pki.cms.verify` keeps `valid: false` for a message whose signature does not verify. The soundness verdict combined the per-signer answers the same way the trust verdict did, so a corrupted signature reported `valid: true`.
- `pki.path.validate` asks its processed-extension tables for their OWN entries. Freezing a table prevents a write to it and does not prevent an inherited lookup, so a name planted on `Object.prototype` answered for every OID the table did not carry and an unrecognized critical extension counted as processed. On a CA certificate only one of the two tables is consulted, so the chain was accepted rather than refused (RFC 5280 sec. 6.1.4).
- A trust anchor's `purposes` map is read for its own entries too. The map is the operator's restriction, and an inherited `true` granted the purpose on every anchor whose map did not name it. `distrustAfter` is read the same way.
- The ML-DSA digest-strength rule (RFC 9882 sec. 3.3) is one question both the signer and the CMS verifier ask, and it answers from the policy table's own entries. A digest name planted on `Object.prototype` answered for every name a parameter set's row omits, so a below-strength digest passed the strength check: `sha256` was accepted for ML-DSA-87 on both paths. The check also had two copies, which is why it now lives in the module that owns the table.

## v0.5.19 — 2026-08-20

The crypto engine and the JWS signer decide with operations captured at load, so code that runs after the module does cannot change what a permission check concludes.

### Changed

- `pki.webcrypto` and `pki.jose` are held to the live-read rule the guard family already follows: the check over `lib/` that refuses reading an operation from the runtime at call time covers every module that takes the captures, and these two now do. Operator-visible behavior is unchanged except where a refusal that could be bypassed now holds.

### Fixed

- The WebCrypto key-usage check holds against a replaced `Array.prototype.indexOf`. The membership test IS the permission decision, so it runs through the captured method: dispatched live, a key permitted only for `verify` passed the engine's gate for `sign` and failed later, in the platform's own crypto, with an untyped fault instead of `webcrypto/invalid-access`.
- A CryptoKey's usage list is a copy this engine took with a captured `slice`, so a replaced one cannot leave the caller holding the array the key is checked against for the rest of its life. The same applies to the partition that decides which usages each half of a generated pair is minted with.
- `pki.key.import`, `pki.key.generate` and `subtle.generateKey` refuse a non-array `usages` by name. It reached the key constructor, where `Array.prototype.slice` on a number yields an empty list, so the call minted a key permitted for nothing rather than naming the argument that was wrong. The asymmetric branch of `generateKey` partitions the usages before either half is constructed and `filter` treats a non-list the same way, so it is checked at that verb's own door and the whole pair is refused.
- The AES-GCM ciphertext and authentication tag are split with a captured `subarray`, so a replaced one cannot hand the tag check a different range of the same buffer.
- A JWK thumbprint (RFC 7638 sec. 3.3) is built with a captured serializer. The canonical JSON is the thumbprint's preimage, so a replaced `JSON.stringify` changes the identity every consumer compares keys by.
- The JOSE header checks -- own-name reads, the `crit` list walk, the embedded-JWK shape test -- and the protected-header serialization all run on captured operations, so a caller who reaches the header through an accessor cannot decide which of them apply.
- A digest runs under the algorithm the caller named. The hash name is case-folded to pick its registry row, and dispatched live a replaced `String.prototype.toUpperCase` answering `SHA-1` gave a caller who asked for SHA-256 a 20-byte digest. The same fold picks the HMAC block size and decides whether a key's algorithm matches the operation's.
- `getRandomValues` settles the kinds WebCrypto refuses from the value's internal slot rather than by `instanceof` against a replaceable global, so a real `Float32Array` cannot pass a check written to reject it by swapping the constructor the comparison names.

## v0.5.18 — 2026-08-20

Every producing verb refuses an authoring field it does not read, so a misspelling is a refusal at the call instead of a signed artifact that quietly omits what was asked for.

### Changed

- The issuer argument of `pki.x509.sign` and `pki.crl.sign` accepts only the fields the form it selects reads: `{ key, cert }` when an issuing certificate is supplied, `{ key, name, publicKey }` otherwise. A caller who hands over a key-store object carrying anything else must narrow it to one of the two. The check is there because a misspelled `cert` is not otherwise refused on this argument -- the issuing certificate is optional, so a dropped one falls through to self-signing, and a cross-certificate issued that way names its own subject as its issuer. Supplying both forms is refused for the same reason: the certificate branch wins unconditionally and reads neither `name` nor `publicKey`, so a caller who named a different issuer got one issued under the certificate's own distinguished name.
- The TSA argument of `pki.tsp.sign` accepts only the certificate and key it reads. A misspelling of either was always refused for what it left missing, but that is half the class: a name belonging on the third argument, written on the TSA instead, is read by nothing there. `ordering` placed on the TSA emitted a token the same size as one that never asked for it, with the flag unset, while the caller believed they had set it. A caller passing a key-store object whole must narrow it to `{ cert, key }`.

### Fixed

- `pki.x509.sign` refuses an unrecognized field on the certificate spec, the issuer and the options. `extension` in place of `extensions` signed a certificate carrying NONE of them: a caller asking for `basicConstraints: { cA: true }` and `keyUsage` got neither, and nothing in the returned certificate said so. An `issuer` nested inside the spec is refused by name as well -- the issuer is the second argument, and nesting it produced a self-signed certificate with no error, which reads as a broken signer rather than a mis-shaped call.
- `pki.crl.sign` refuses an unrecognized field on the CRL spec, the issuer and the options. The revoked list is `revoked`; the parser reports the same list as `revokedCertificates`, so a caller round-tripping a parsed CRL back into signing reached for that name and got a correctly signed, structurally valid CRL asserting that nothing is revoked. The refusal names the field the producer reads.
- `pki.pkcs12.build` refuses an unrecognized field on the store spec and the options, and no longer accepts an option belonging to `open` or `verifyMac`. A store that silently omits a certificate or a key looks well formed and opens cleanly; the omission surfaces wherever it is later imported.
- `pki.pkcs12.build` refuses an unrecognized field on a `safeContents` entry, on a bag, and on the PBE descriptor either of them carries. The safeContents entry is where the privacy directive lives, so a misspelling there was the costliest in the format: `encrypt` misspelled is neither present nor falsy, so it passed the guard that rejects a present-but-falsy directive, no privacy was selected, and that safe went out as plaintext `id-data` -- an unshrouded private-key bag in the clear, inside a PFX whose MAC still verified and which opened without complaint. A misspelled PBE parameter, on either the safe or the bag, silently reverted to the built-in default, so a caller who asked for a stronger KDF or a different cipher got neither. `opts.mac` is checked the same way, and every one of its fields has a default too: a misspelled `iterations` produced a store MAC'd at the shipped iteration count while the caller believed they had raised it, and an array passed as `opts.mac` carried no field any table lists, so it reached the builder as an empty descriptor and produced the default MAC.
- `pki.pkcs12.build` refuses a spec that mixes its two forms. `safeContents` and the `{ key, cert, ca }` shorthand are alternatives, and the builder returns `safeContents` the moment it is present without ever reading the shorthand fields -- so `{ safeContents: [...], key }` produced a store with the key silently absent.
- A `safeContents` entry is checked against the privacy branch it selects. `contentEncryptionAlgorithm` is the public-key branch's content cipher and is read by nothing on a password safe, whose cipher comes from `encrypt.cipher`, so an explicit `aes-128-cbc` request on a password safe was accepted and the default used anyway.
- A certificate recipient of `pki.cms.encrypt` is checked against the fields ITS CERTIFICATE'S KEY ALGORITHM reads. The arms differ: RSA reads `oaepHash` and never `ukm`; ECDH, X25519, X448 and ML-KEM read `ukm` and never `oaepHash`. One table across all three accepted `oaepHash` on an elliptic-curve recipient, where nothing reads it, and wrapped the content key under the arm's own defaults.
- A bag is checked against the fields ITS OWN TYPE reads, rather than against one table covering every type. `encrypt` is real on a `shroudedKey` bag and read by nothing on a plaintext `key` bag, so a union accepted the combination and emitted the private key as an unencrypted key bag while the caller had supplied an explicit encryption directive and the surrounding MAC gave integrity only.
- `pki.crl.sign` refuses an unrecognized field on a revoked-certificate entry. Every optional field on an entry is encoded only when present, so `reson` in place of `reason` listed the certificate as revoked carrying no reason code at all -- in a CRL that verifies, where a relying party cannot distinguish it from a revocation published without a reason.
- `pki.cms.encrypt` refuses an unrecognized field on a recipient descriptor, against a table per recipient type. The fields beyond the selector all have defaults, so `oaepHsh` encrypted the content key under the default SHA-256 OAEP, and a misspelled `iterations`, `salt` or `prf` on a password recipient derived the key at the default work factor. The single descriptor an `EncryptedData` takes is checked per arm as well: its `cek` branch derives nothing, so a work factor handed to it was discarded exactly as a misspelling would be.
- `pki.tsp.sign` refuses an unrecognized field on the `accuracy` descriptor. Its three fields are all optional, so `milis` emitted an empty Accuracy that reads back as zero seconds, millis and micros, and the token understated the precision the caller asked it to claim.
- `pki.cms.encrypt` and `pki.cms.authenticate` each refuse an unrecognized option, against separate tables. The two verbs have different option sets, so a single shared table would have accepted either verb's keys and defeated the check.
- `pki.tsp.sign` refuses an unrecognized field on the message imprint and the options. A one-letter slip -- `odering` for `ordering` -- emitted a token with the ordering flag unset, which is a claim about the timestamp the caller believed they had made.
- `pki.pkcs12.open` and `pki.pkcs12.verifyMac` each refuse an unrecognized option, against their own tables. `maxIterations` caps the work a hostile store can demand of the key derivation, so a misspelling restored the built-in ceiling and the tighter bound the caller set was never applied.
- `pki.tsp.request` refuses an unrecognized field on the message imprint as well as on the options -- the same table `pki.tsp.sign` holds its imprint to. The request's own options are the second argument, so `nonce` written on the imprint reached nothing and the request went out with no nonce.
- `pki.tsp.request` refuses an unrecognized option. Every field it encodes is optional in the request structure, so a misspelled one was dropped without complaint: `nonce` misspelled put a request on the wire carrying no nonce at all, and the client then matched the reply against a replay defense it had never actually asked for.
- `pki.tsp.response` refuses an unrecognized option. `status` carries the verdict and defaults to granted, so a misspelling did not lose a detail -- it inverted the answer, and a TSA declining a request emitted a granted response over a token it meant to withhold.
- The options of `pki.pkcs12.build` are checked against the spec form in force. `recipientCerts` selects public-key privacy only where the builder assembles the safes itself, so under the `safeContents` form it selected nothing: a plaintext key bag went into an `id-data` safe with the private key in the clear, while the caller had asked for recipient-enveloped privacy. The full form carries privacy per entry, as `safeContents[i].recipients`.
- `pki.cms.encrypt` and `pki.cms.authenticate` refuse a per-recipient default that no recipient of the message reads. `oaepHash` is read only by an RSA certificate recipient, `ukm` only by a key-agreement or KEM certificate recipient, and `keyIdentifier` only by a certificate recipient -- so a password-only message given an `oaepHash` described a wrapping it never performed. A recipient that supplies its own value reads that one and never the default, so a default every recipient overrides is refused too; one recipient that does read it is enough. An `EncryptedData` carries no recipients at all and so reads none of the three.
- `pki.cmp.build` refuses a signature parameter under MAC protection. `pss` and `digestAlgorithm` are read only by the `{ key, cert }` form; supplied alongside `mac`, they emitted a message MAC'd under the default PRF, byte for byte identical to the call that never named them.
- `pki.jose.sign` refuses `opts.jwk` when the protected header already embeds one. The embedded key wins, so the option is read in kid mode only, and a caller who named a different public JWK beside an embedded one had it discarded.
- `pki.jose.sign` serializes the protected header once and every check reads back those exact bytes, through the same bounded reader a received JWS goes through. The header is a caller-owned object, so a `toJSON` or an accessor could answer the public-only check and the serializer differently: a JWK whose own members carried no private half but which serialized `d` passed the check and shipped the private key in the header. Serializing runs that code, so the option check now runs before it -- a `toJSON` reaching into the options bag could otherwise delete a misspelled option before the door looked at it. A header that cannot be serialized is refused rather than reaching the signer.
- `pki.pkcs12.build` decides which of the two spec forms it has once, and the field check and the builder both act on that decision. Held separately the two tests disagreed on a `safeContents` that is present but not a list, so the refusal named a field that was correct instead of the one that was wrong.
- `pki.cms.encrypt` refuses `authAttrs` under a CBC content algorithm. Authenticated attributes are carried by an `AuthEnvelopedData`, which an AEAD algorithm produces; a CBC algorithm selects `EnvelopedData`, which has no field for them, so the attributes a caller asked to authenticate were dropped and the message went out without them.
- `pki.cms.authenticate` refuses `digestAlgorithm` and `authAttrs` when `authenticatedAttributes` is `false`. That branch MACs the content octets directly and builds no attribute set, so the digest algorithm that names its hash, and any attribute added to it, are read by nothing.
- `pem` on an `EncryptedData` descriptor is refused; it is an option, the third argument, as on every other verb here. A second spelling on the descriptor was read by the password arm alone, so a `{ cek, pem: true }` descriptor was accepted and returned DER.
- `pki.crl.sign` refuses `spec.issuer` when the issuer argument already names one. The distinguished name has three possible sources and `issuer.cert` and `issuer.name` both win outright, so a spec naming one issuer beside a certificate for another produced a CRL, which verifies, issued under the certificate's name. `spec.issuer` is still the name when the issuer argument supplies none.
- `opts.mac.keyLength` on a `pki.pkcs12.build` store is refused under the classic `hmac` algorithm, which is the default. The Appendix B derivation produces a key at the hash's own output length and reads no key length, so an explicit one was discarded and the store carried the same MAC as a call that never named it. `keyLength` remains a PBMAC1 parameter (RFC 9579).
- A `pki.pkcs12.build` public-key integrity signer is checked against the form it selects, `{ cert, key }` or `{ spki, keyIdentifier, key }`, plus the signature parameters. Every field beyond the identity has a default, so a misspelled `pss` or `digestAlgorithm` signed the store under PKCS#1 with SHA-256 while the caller had asked for something else, and a store records only what was used. `opts.integrity.signer` and `opts.integrity.signers` are the same setting spelled two ways and the list won outright, so supplying both signed the store under the list alone; exactly one is now required.

## v0.5.17 — 2026-08-20

A failed integrity check destroys the plaintext it recovered, AuthEnvelopedData validates the attributes it is asked to authenticate, and every refusal names the rule it is actually applying.

### Changed

- The refusals for a content cipher in the wrong container now cite the rule they apply. RFC 5083 sec. 2 defines `AuthEnvelopedData` in terms of a content-authenticated-encryption algorithm; it never names GCM, and RFC 5084 sec. 3.1 defines AES-CCM for that content type. Saying the standard required GCM sent an operator to argue with a specification that says the opposite. The check now draws the line the RFC draws -- authenticated versus not -- and an AES-CCM message is declined separately, by name, as an algorithm this toolkit does not implement rather than as an unrecognized OID. Error codes are unchanged.
- Documentation pages at pkijs.com carry the expanded name of the format they describe in the title and heading, so a page about CMS says Cryptographic Message Syntax rather than three letters that mean a content management system elsewhere. The sitemap now reports each page's real last-changed date, taken from the commit that last touched the source it is generated from, and omits the date where it is unknown instead of reporting the build time. The home page gained runnable examples for the six things people most often arrive wanting to do.

### Fixed

- A failed AEAD integrity check now destroys the plaintext it recovered. `update` returns the complete recovered plaintext and `final` is what decides whether the message was authentic at all, so on a forged `AuthEnvelopedData` the plaintext existed in full before anything had judged it, and the buffer was then dropped unreferenced and unzeroed. RFC 5083 sec. 1 requires it to be destroyed. The success path leaked too, less visibly: joining the two halves copies them, leaving the first buffer as a second complete copy of the plaintext that the caller never receives and nothing else would ever clear. Both exits are now cleared, at every cipher the toolkit runs -- CMS content decryption and the RFC 3211 password-recipient unwrap, PBES2, HPKE `open`, PKCS#12 safe decryption, and the AES-GCM, AES-CBC, AES-CTR and AES-KW paths of the WebCrypto engine.
- `pki.cms.encrypt` validates the authenticated attributes a caller supplies for an `AuthEnvelopedData` before it MACs them. Each must be a well-formed `Attribute SEQUENCE { type, non-empty SET OF value }` with no repeated type (RFC 5652 sec. 5.3). `AuthenticatedData` had enforced this all along; `AuthEnvelopedData` accepted whatever it was handed and emitted it, so a malformed attribute reached the wire with the MAC already computed over it and the operator learned of it from a peer's parser rather than from the builder.
- `pki.cms.encrypt` refuses a `message-digest` attribute in an `AuthEnvelopedData`'s `authAttrs`. Its value is the unencrypted one-way hash of the plaintext, so disclosing it alongside the ciphertext enables content tracking and confirms a guessed plaintext against a message that was encrypted to prevent exactly that (RFC 5083 sec. 2.1 and sec. 5). Decryption still accepts one, since another implementation may legitimately emit it; the toolkit will not produce one. `AuthenticatedData` is unaffected -- it builds and MACs its own `message-digest` by design (RFC 5652 sec. 9.2).

## v0.5.16 — 2026-08-19

`pki.cmp.verify` reads every option at the call, and every guard takes what it needs from the runtime when it loads, so code a caller runs afterwards cannot change what a verification decides.

### Fixed

- `pki.cmp.verify` reduces every option to a value the caller no longer reaches, before verification begins. `transactionID` and `expectRecipNonce` are copied, so overwriting the buffer that was passed in changes nothing; `trustAnchors` and `intermediates` have their array copied, so appending an anchor mid-call cannot widen the set the chain is built against; and a `time` that is a real `Date` is re-made at the same instant, so calling `setTime` on it cannot move the point the signer's certificate is validated at. A `time` that is not a `Date` passes through untouched, so the input error it already earns is the one it still gets.
- `pki.cmp.verify` now takes its options through the same door every other verb uses, which it had been skipping in favor of two checks of its own. The door refuses an options object whose fields are accessors, and one that changes which fields it carries while they are read. An accessor is caller code running inside the call before the verb has done anything, and from there it can rewrite the very predicates and constructors the verb is about to use, so refusing it closes that whole class rather than one member at a time. What is asked of a caller is only that the options themselves be values.
- A `sharedSecret` given as a string is converted to bytes with a `Buffer.from` captured when the module loads. `Buffer.from` is a writable property of the `Buffer` global and the secret is the first option read, so the accessor supplying it could install a replacement, receive the plaintext as that replacement's argument, and have whatever it returned become the PBMAC1 key -- a message authenticated under a secret the caller never held would then verify. The captured reference is fixed before any caller code has run.
- A `sharedSecret` given as a string is converted to bytes once, at the door, and that copy is cleared with the rest. The conversion is what produces a wipeable plaintext copy, and it used to happen deeper inside the MAC path where nothing owned it, so the toolkit left a copy of the secret behind on every call. The string itself is immutable and cannot be cleared, which is still the reason to hand over bytes when the secret must not outlive the call.
- Whether a byte option is copied, and whether that copy is later wiped, is decided by asking the value's internal slot rather than its prototype. `Buffer.isBuffer` is a writable property and `instanceof Uint8Array` consults `Uint8Array[Symbol.hasInstance]`, and both are reachable from an option accessor that has already run by the time the test is evaluated. A caller who made those answer `false` for their own buffer got the copy skipped, which left their live buffer where the copy belongs -- and the wipe then cleared memory the toolkit does not own.
- The copies go through `guard.bytes.snapshot`, this toolkit's door for caller-supplied bytes, so a source the door refuses stays refused. A view backed by a `SharedArrayBuffer` is the case that matters: another thread can rewrite it at any moment, and copying it with `Buffer.from` would have turned it into an ordinary `Buffer` that every later check accepts without the door's rules ever having run.
- Each option is read from the caller's object exactly once and copied in the same step, before the next option is read. A property can be an accessor: asked twice it may answer differently, so the value that passed the check would not be the value that was used; and an accessor invoked for a later option can reach back and rewrite the buffer an earlier one handed over, so reading the whole bag before copying any of it would copy whatever the last accessor left behind.
- `opts.trustAnchors` and `opts.intermediates` must be a plain dense array (or a single certificate). A list with holes, or one whose elements are reachable only through its prototype, is refused with `cmp/bad-input` naming the problem. Reproducing what an ordinary array operation would consume means handling holes, inherited and non-enumerable elements, and the uint32 index boundary, and those pull against each other: reading every position covers inheritance but scans a sparse list's whole length, while enumerating present keys is bounded but silently drops an inherited anchor -- and dropping an anchor turns a trusted verification into an untrusted one. Refusing is the answer this verb gives instead of choosing quietly. No ceiling is imposed on how many anchors a dense list may hold.
- Two things stay caller-owned by design, and the release is explicit about them. A parsed certificate passed as an anchor or an intermediate is held by reference, because `pki.schema.x509.parse` results carry their provenance against the object's identity and a copy would stop being recognized as parser output; editing one mid-call changes nothing, since path validation re-derives a parsed certificate from the bytes it recorded. And a `revocationChecker` is the caller's own callback, so what it answers is theirs to decide whenever it is called.
- `pki.cmp.verify` refuses a Proxy-wrapped certificate list before it reads anything from it. A Proxy over an array reports itself as an array while answering from traps that need not agree with one another, so a count taken through them describes nothing that is still true by the time the anchors are used. Refusing a Proxy was already this toolkit's answer for a value it cannot ask honestly; that refusal now runs ahead of the length read and the descriptor walk, which would otherwise be the first thing to hand control back to the caller.
- Every guard that performs its work with a method captured at load now invokes that method without reading any property of it. Capturing freezes which function runs, so replacing the prototype method afterwards changes nothing; invoking it as `captured.call(receiver, ...)` then read `call` off the captured function, and that function is the one still sitting on the prototype. Assigning an own `call` to it shadows `Function.prototype.call` and hands the guard back to the caller with every check around it still passing: the secret wipe clears nothing, two unrelated distinguished names compare equal, a decode returns a string the caller chose, the instant a certificate is validated at becomes whatever the caller says, and a byte view reports a length and a backing store it does not have.
- Every operation the guard family performs while it is deciding something is taken from the runtime when the module loads, rather than at the moment it runs. That covers the reflective operations a guard inspects a value with, the predicates that answer what a value IS, the `Buffer` and `Promise` constructors, the numeric and array tests bounds are built on, and the string operations names and encodings are compared with. It also covers the array operations a guard walks its own lists with, where a `forEach` replaced by a no-op made a scan over real keys report nothing and every rule keyed on that scan then passed without examining anything. The whole family is driven with twenty-three of those globals replaced at once and each guard still reaches the answer it would have reached untouched. A check over the source refuses any guard that reads one of these at call time, so the rule holds for a guard written later without anyone remembering it.
- Canonicality takes both halves of its round trip at load, and the size cap measures a Buffer through the byte guard's captured length getter. Canonical form is decided by decoding the text and re-encoding the result, so either half settles the answer: a `toString` returning the input made `AB` compare equal to its own re-encoding and pass as canonical base64url, where its canonical form is `AA`. On a typed array `length` is a configurable accessor on the prototype, and the cap comparison read it, so one returning 0 admitted a buffer of any size and then decoded it in full.
- The `Buffer` constructor that turns a backing store into something the toolkit can read or clear is taken at load. It sits behind the re-view every byte boundary performs, so one returning a buffer over different memory handed each later step a decoy: a wipe zeroed the decoy and returned normally while the plaintext it was aimed at stayed readable, with every check in between satisfied. The same reference now backs the canonical-encoding round trip, where a replacement decides what that comparison sees, and the provenance copy, where it decides whether recorded bytes can still change afterwards.
- The index scan behind the accessor refusal asks the array question through a reference taken at load. A replacement answering `false` made the scan report no indices, so the refusal had nothing to refuse and an accessor under index 0 was reached by the copy that follows it -- the caller's own `Error` escaping a boundary whose contract is a typed refusal, with the accessor free to run before anything it returned was snapshotted. The same reference now backs the array questions in the byte-source, parsed-structure and identifier guards.
- The two predicates that decide whether a `pki.cmp.verify` option gets copied are taken at load rather than at the call. Both are ordinary writable properties, so reading either at call time handed that decision to the caller: an `isUint8Array` answering `false` left a live caller buffer where the copy belongs and left that buffer out of the list the call wipes, and an `Array.isArray` answering `false` routed a trust list past the list door and back out by reference, ready to be emptied or appended to while verification was suspended.
- The slot predicates a guard asks about a value are snapshotted at load, and so is the check that a `Date` holds a real instant. `util.types` is an ordinary object on an ordinary module export, so `util.types.isDate = () => true` reached every guard that asked it at call time; these predicates are how the toolkit decides what a value IS, in preference to a prototype test a caller can satisfy, so a caller answering them instead had replaced the one question a lookalike cannot lie about. The global `isNaN` was read the same way, and one returning `false` made `new Date(NaN)` pass the validity check that stands in front of every window comparison.
- The wipe that clears a secret the toolkit allocated writes its zeros through a fill captured when the module loads. `Buffer.prototype.fill` is a writable property, and it was the entire operation the wipe performed: replaced with a function that writes nothing, every wipe in the toolkit became a silent no-op. Nothing observable changed when that happened, since the wipe was still called and still returned, while a shared secret or a content-encryption key stayed readable in the heap after the call whose only purpose was to clear it.
- Distinguished-name comparison takes its string operations from the prototypes at load. Every value it compares is a plain string, so `value.toLowerCase()` reached whatever `String.prototype` carried at the moment it ran, and that is an ordinary writable property. One returning a constant made every DN compare equal to every other, which is the whole of what this comparison decides: chain building would accept an unrelated issuer, a revocation entry would match a certificate it was never written for, and a name constraint would stop excluding anything. The DN escaping used in reports and the control-byte reject that defends CVE-2009-2408 read characters and character codes the same way, and the same change covers them. `Array.isArray`, which decides whether a comparison can be performed at all, is captured alongside them; replacing that one points the other way, turning every name comparison the toolkit makes into a refusal.
- Decoding untrusted bytes to a string does its work through references captured at load, on both of its input arms and in both of its contracts. `Buffer.prototype.toString` produced the guard's entire output for a Buffer and `TextDecoder.prototype.decode` did the same under strict UTF-8, so replacing either handed the boundaries that compose it -- PEM headers, JOSE segments, DN attribute values -- a string the caller chose, with the size cap, the detached-view refusal and the strict-UTF-8 rule having all run and all passed. `Buffer.byteLength` measures a string against that cap, and one returning a small number admitted a string of any size, which is the allocation this guard exists to bound. `Number.isInteger` decides whether the cap is usable and `Buffer.isBuffer` decides which arm an input takes; both are captured for the same reason.

## v0.5.15 — 2026-08-19

`pki.attrcert.verify` checks an attribute certificate against the RFC 5755 validation rules, so a consumer reading its privilege attributes is reading ones an issuer actually granted.

### Added

- `pki.attrcert.verify(ac, issuer, opts)` performs the checks of RFC 5755 sec. 5 that an attribute certificate and a named issuer can settle between them: the signature over the exact `AttributeCertificateInfo` bytes, through the one path-validation signature engine with its algorithm-confusion and EdDSA low-order-point gates; the AC naming the issuer this verifier trusts; the evaluation instant lying within the validity, where equality with either bound succeeds as the section states; the sec. 4.3.2 targeting rule, where an AC that names targets is refused at a verifier it does not name; and rejection of any critical extension this verb does not process. Section 5 defines support as parsing the value AND rejecting where the value would reject, so an extension parsed but never evaluated is not supported: targeting is processed and an audit identity states no rule that rejects, while `aaControls` and `acProxying` carry constraints this verb does not evaluate, so a critical one is refused, and a critical extension defined in future defaults to refused. Targeting compares each GeneralName form under its own matching rule: a dNSName folds case across the whole name (RFC 5280 sec. 7.2), a mailbox matches its local-part exactly and its host-part case-insensitively (sec. 7.5), and a directoryName goes through the same distinguished-name comparison the rest of the toolkit uses. A URI compares as encoded, since sec. 7.4 makes URI equality a full RFC 3987 normalization that a partial version could get wrong in the accepting direction; a form with no comparison here reports the check as not performed rather than as a pass. The third Target alternative, targetCert, is one sec. 4.3.2 says "MUST NOT be used", so an attribute certificate carrying one is refused before any match is considered, and a matching entry beside it does not rescue it -- the issuer broke a MUST NOT of its own profile, and letting the verdict turn on which entries rode alongside the forbidden one would leave the outcome to whoever assembled the certificate.
- `issuer` is `{ name, publicKey }` and is required. Section 5 item 4 makes trusting an AC issuer the verifier's own configuration, so it is an argument this verb refuses to infer from the certificate that wants to be trusted. `issuer.name` takes every form `pki.attrcert.sign` accepts for the issuing authority -- a string, an array of RDNs, or raw `Name` DER -- and is compared as a distinguished name under RFC 5280 section 7.1, so an attribute certificate issued under a multi-RDN authority name is verifiable under that same name. An empty distinguished name names no issuer and is refused, whichever form it arrives in.
- Revocation is RFC 5755 section 6, outside section 5's seven rules, and it gates every pass. This verb implements the section's "never revoke" scheme, which AC users MUST support: it holds no revocation evidence and follows no pointer out of the certificate. The section states what that obliges -- "If only the 'never revoke' scheme is supported, then all ACs that do not contain a noRevAvail extension, MUST be rejected" -- because an issuer that omits `noRevAvail` is stating that revocation status checks are supported, so a verdict that skipped one would grant privileges the issuer expected to be able to withdraw. An attribute certificate carrying `noRevAvail` verifies and reports `revocationChecked: true` with `noRevAvail: true`. One without it is refused unless the caller passes `opts.revocationStatus` (`"notRevoked"` or `"revoked"`), the status they established through the section's "pointer in AC" scheme; the certificate's own `crlDistributionPoints` and `authorityInfoAccess` reach them on the verdict's `extensions` to follow. The two schemes are alternatives, and section 6 closes by saying so -- "An AC MUST NOT contain both a noRevAvail extension and a 'pointer in AC'" -- so an attribute certificate carrying both tells a verifier two different things about its own revocation and is refused however the caller answers.
- `opts.time` and `opts.target` are read at the call, before signature verification suspends it. A verdict assembled from options re-read after the signature settles would answer for whatever the caller last wrote, so a caller could hand in an expired instant, replace it while the signature was being checked, and be told the attribute certificate was timely. Mutating the `Date` in place has the same effect and is closed the same way: the instant is taken at the call, and the target is decoded there. `issuer.publicKey` is copied at the call for the same reason. The signature engine holds that buffer across the suspension, and a composite arm keeps slices of it and imports them only once its digest settles, so a caller could otherwise hand in an unrelated key of the same length, overwrite it with the real issuer's while the digest ran, and be told the certificate verified under the key they named.
- The verdict is `{ verified, signatureValid, validityChecked, targetingChecked, revocationChecked, noRevAvail, holderBindingChecked, issuerPathChecked, holder, issuer, attributes, extensions, notBefore, notAfter, serialNumberHex, reason }`, its fields re-derived from the signed bytes. The two checks needing certificates this verb is not given -- the holder's own certificate and chain, and the AC issuer's chain and sec. 4.5 profile -- report `false` in their own slots rather than leaving their absence to read as a pass; run those through `pki.path.validate` with the certificates you hold. Omitting `opts.time` leaves the validity question unasked, which reports `validityChecked: false` and never `verified: true`.

### Changed

- `pki.attrcert.sign` refuses to issue an attribute certificate carrying both a `noRevAvail` extension and a `crlDistributionPoints` or `authorityInfoAccess` revocation pointer, which RFC 5755 section 6 says an AC MUST NOT do. The rule is held over the extensions the certificate ends up with, so it binds the named-extension form and the pre-encoded DER form alike.
- `pki.schema.attrcert.parse` now records the bytes it read, joining the certificate, CRL, CMS, certification-request and certificate-request-message parsers, and `pki.attrcert.verify` accepts only a result carrying that record. A parsed attribute certificate presents the signed byte range and the attributes granting the privileges as separate properties, so a rebuilt one can hold a genuine issuer's signed bytes beside substituted attributes. As with those parsers, the raw byte views on a parsed result now read from the parser's own copy of the input; passing DER or PEM is unaffected.

## v0.5.14 — 2026-08-19

`pki.crmf.verifyPop` checks the proof of possession on an inbound certificate request message, the CRMF counterpart to the PKCS#10 check that shipped in 0.5.13.

### Added

- `pki.crmf.verifyPop(messages)` verifies the RFC 4211 proof of possession on each `CertReqMsg`, returning one verdict per message plus a top-level `verified` that is true only when every message carried a proof that held. For the `signature` proof the covered bytes are the ones the RFC names: the DER of `poposkInput` when that field is present, and the DER of `certReq` when it is absent (sec. 4.1, and the ASN.1 module, which is where the two readings of that sentence are settled). Verification composes the one path-validation signature engine, with the same algorithm-confusion (RFC 9814 sec. 4) and EdDSA low-order-point gates as the certificate and CRL paths.
- The proofs that cannot be checked from the message are reported as such. `raVerified` is an RA's assertion that it confirmed possession out of band, so it yields `verified: false` with `method: "raVerified"`, and a caller who trusts that RA opts in by reading `method`. `keyEncipherment` and `keyAgreement` complete over a later protocol exchange, or need the CA's decryption key, so they yield `verified: false` naming the arm. Each verdict carries only what its preimage covers, re-derived from the message's own bytes, so a CA issues from what was checked. `publicKey` is the key possession was proven for. `subject` is the requested name when the signature was over `certReq`, which covers the whole template; a `poposkInput` preimage covers the key and the sender alone, so a subject sitting beside it in the message is unsigned and is withheld with `subjectBound: false` rather than reported next to a passing verdict.

### Changed

- `pki.schema.crmf.parse` now records the bytes it read, joining the certificate, CRL, CMS and certification-request parsers, and `pki.crmf.verifyPop` accepts only a result carrying that record. A parsed message set presents the byte range a proof covers and the template a certificate would be issued from as separate properties, so a rebuilt one can hold a genuine requester's signed range beside a substituted subject. As with those parsers, the raw byte views on a parsed result now read from the parser's own copy of the input; passing DER is unaffected, and a parse result used as-is still works.

### Fixed

- The `pki.csr.sign` example passed `subject: "CN=device-42"`, which asks for a commonName whose value is the string `CN=device-42` and so issues `CN=CN=device-42`. A bare string is the commonName value throughout the toolkit; the example now says so and passes `"device-42"`.

## v0.5.13 — 2026-08-19

`pki.csr.verify` checks an inbound certification request's proof of possession, so a CA built on this toolkit can tell that the requester holds the key they are asking it to certify.

### Added

- `pki.csr.verify(request)` verifies a certification request's signature over its exact `certificationRequestInfo` bytes under the `subjectPKInfo` inside them (RFC 2986 sec. 4.2), the check `openssl req -verify` performs. `request` is DER, PEM, or a parsed request. It composes the one path-validation signature engine, with the same algorithm-confusion (RFC 9814 sec. 4) and EdDSA low-order-point gates, in place of the producing side's self-check, which waives that gate because it runs over a key the caller already controls. It fails closed on any import or verification fault, and malformed input throws a typed `CsrError`.
- The answer is `{ verified, subject, subjectPublicKeyInfo, attributes, certificationRequestInfoBytes }`, every field re-derived from the bytes the signature covers. Issue from those. A CA that normalizes a request before verifying it holds an object carrying its own edits, and a bare boolean would report on the signed bytes while the certificate got built from the edits; the fields travel with the verdict so the two cannot come apart.
- What `verified: true` establishes is stated in full, because the bound is the point: the producer held the private half of the key inside the request, and the subject and every requested extension are the ones covered by that signature. A CSR carries no issuer and its key is self-asserted, so a requester free to choose both can prove possession of a key they generated a moment ago under any name they like. Binding that name to an identity stays with the enrollment protocol.

### Changed

- `pki.schema.csr.parse` now records the bytes it read, the way the certificate, CRL and CMS parsers do, and `pki.csr.verify` accepts only a result carrying that record. A parsed request presents the signed byte range and the fields that range encodes as separate properties, so a rebuilt one (`Object.assign`, a spread, a JSON round-trip) can hold a genuine requester's signed bytes beside a substituted subject: the proof of possession verifies from the recorded range while the certificate a CA issues is for a name nobody signed. Passing DER or PEM is unaffected, and a parse result used as-is still works.
- One visible consequence of that record: the raw byte views on a parsed request (`certificationRequestInfoBytes`, `tbsBytes`, `subject.bytes` and the rest) now read from the parser's own copy of the input rather than from your buffer, matching what `pki.schema.x509.parse` has always done. Writing into the buffer you passed no longer changes what an already-parsed request reports, and writing through one of those views no longer reaches your buffer. Code that read the fields is unaffected; code that relied on either aliasing needs to re-parse instead.

## v0.5.12 — 2026-08-19

`pki.crl.isRevoked` can be asked at an instant, and a CRL that stopped speaking for that instant is refused rather than read as a clean bill of health.

### Added

- `pki.crl.isRevoked(crl, serialNumber, { time })` asks the question at an instant. A CRL whose `nextUpdate` has passed, whose `thisUpdate` is later, or which carries no `nextUpdate` at all is refused with `crl/not-current` instead of answered from: outside the window a CRL states, an absent serial says nothing about the certificate, and a list stating no window cannot be told from a replayed copy. This joins the refusals already made for a delta, indirect or narrowed-scope CRL, on the same reasoning -- a serial means something only within the set, and the span, a CRL speaks for. `pki.path.crlChecker` is unchanged and remains the verb that decides currency against material it fetched itself.
- `opts.historicalMode` reads a revocation entry against that same instant, the way `pki.path.crlChecker` reads one. By default a listed serial is revoked whatever its `revocationDate` says, since a date in the future is post-dating or clock skew and must not read good; set `historicalMode` -- validating as of a past instant, a timestamped signature say -- and an entry dated after that instant has not yet applied. Given without `time` it names no instant to read against and is refused.

### Changed

- `pki.crl.isRevoked` takes a third argument. It is optional and every existing call keeps its behavior and its answer: without `time` the verb is the structural lookup it has always been, and its documentation now names the question that then goes unasked, so `null` reads as "not listed on this CRL" rather than "not revoked". An option it does not read is refused rather than ignored.

## v0.5.11 — 2026-08-18

An option a verb never reads is now refused, so a misspelled `password` on key export can no longer leave a private key unprotected.

### Changed

- `pki.key` (encrypt, decrypt, export, import, generate, publicFromPrivate), `pki.path.validate`, `pki.path.build`, `pki.lint.certificate` and `pki.ocsp` (buildRequest, sign, verify) throw `<domain>/bad-input` on an option they do not read, instead of ignoring it. A call passing an option that did nothing before will now fail; the message names the unknown key, so the fix is to correct or drop it.
- The same verbs require an options object whose options are values. One supplied through a getter is refused, naming the option, because a getter is asked afresh on every read and the value the check saw is not necessarily the one the verb uses. A caller computing an option can read it into a plain object at the call: `pki.key.export(key, { format: computeFormat() })`. Methods are unaffected, so a class instance carrying them is still an options bag.
- Where two verbs spell the same idea differently, the refusal says so. `pki.path.validate` takes `trustAnchor` and `pki.path.build` takes `trustAnchors`, and each names the other, because carrying the wrong spelling between them previously bought no anchoring and no error. `pki.key.encrypt` chooses `iterations` while `pki.key.decrypt` caps `maxIterations`; `pki.ocsp` spells the nonce three ways across buildRequest, sign and verify because it means three different things.
- `pki.path.build` accepts every `pki.path.validate` option, since it forwards them to each internal validation. That union is derived from validate's own list rather than restated, so the two cannot drift apart.

### Fixed

- `pki.sigstore.verifyBundle(bundle, { time })` validates the Fulcio chain at the instant the Date holds. `time` is accepted by its internal slot, so a Date subclass reaches the check; the instant was then read back through `getTime`, which a subclass answers. A caller-supplied Date reporting the log time made the ephemeral signing certificate, whose validity is about ten minutes wide, look current whenever the caller chose to check it. Every read of a Date across the toolkit now goes through the intrinsic, so what a comparison uses is the instant a Date holds rather than the one it reports.
- `pki.path.validate` and `pki.ocsp.verify` decide the validity window on the instant a Date holds. Both compared the caller's `time` against a certificate's, CRL's or response's Date as objects, and comparing two Dates coerces each one through `Symbol.toPrimitive` or `valueOf`, which a caller's subclass answers. `path.validate` checked `opts.time` for a valid instant at entry and then compared it through a door that check never used, so a Date holding one moment and reporting an earlier one made an expired certificate validate. Both now narrow every operand to its held instant before comparing.
- A field inherited from an object a caller built over the prototype every typed array shares is reported as the unknown option it is. The kinds were recognized from that shared parent, so any level minted the same way read as one the language installs members on, and a bag inheriting `BYTES_PER_ELEMENT` from it reached `pki.key.generate` unremarked. The concrete kinds are now found by asking the runtime for them and matched by identity, which keeps a kind added later covered the day it lands without admitting anything that merely sits above the same prototype.
- A key from another WebCrypto implementation reaches the verb even where that implementation keeps its internals under a symbol. Every verb reads its options by name, so nothing under a symbol key can be read as one, and refusing a handle for carrying one protected nothing while turning a documented input away. The options door is unchanged and still reports a symbol on a bag passed as options, which is the case that matters: a caller who wrote one there meant it as an option and no verb will read it. A name a verb could read is still refused on a key handle.
- A `node:crypto` KeyObject reaches the verb it was passed to. `pki.hpke` documents one as a key input, and its material lives behind an internal slot, so what a copy holds is the shape of a key and none of the key: the object the verb received could not export, sign or derive. It is now recognized from that slot and handed on as itself, which is how a WebCrypto CryptoKey was already treated. A value wearing `KeyObject.prototype` with no key behind it is still copied, and the raw `TypeError` its `type` getter raises is now the calling module's typed refusal with that fault as its cause.
- The tables naming what each uncopyable kind carries no longer answer for names they inherit. Built as ordinary objects, a table answered `toString` with the function every object in the language inherits, so `toString`, `constructor`, `valueOf`, `hasOwnProperty` and `__proto__` read as published surface on a `RegExp`, an `Error`, a `CryptoKey` and a thenable alike. A caller could write any of the five onto such an object and have it handed to a verb by reference. Membership is now a fact about the table.
- A field written with `Object.defineProperty` is seen by the check that decides whether a handle may be passed on by reference. A `RegExp`, an `Error`, a key handle and a thenable cannot be copied, so a verb receives the caller's own object and a field on it stays the caller's to change after every check has read it. That check passed over non-enumerable properties on the reasoning that a caller adds fields by assignment; `Object.defineProperty` belongs to a caller as much as to a platform, so a `RegExp` from another realm carrying a hidden `detached` reached `pki.cms.sign`, and flipping it after the call moved the content out of the message the call had already been asked to sign. What is asked now is whether the property can still move: a field that is writable, configurable, or backed by a getter is refused, and so is one whose value can move even where the binding cannot, since a frozen slot holding a `Date` is an instant anybody can still change. A field that is settled through to its value rides along, which is how an implementation writes the internal state a key handle carries.
- A `Date` copy answers every `Date` method the way a `Date` holding that instant answers. A method written onto the value itself shadows the language's, and the copy carried it: an own `getUTCFullYear` that throws came across onto the copy and threw out of `pki.cms.sign` while the signing time was being encoded. The names the language supplies are read off `Date.prototype`, and what decides is the value rather than the name: a function under one of those names is behavior and is left behind, while a plain value under the same name is a field and comes across, so an option misspelled as `getTime` still reaches the check that refuses an option no verb reads.
- An element supplied through a getter is refused where a field already was. The deep copy taken at a verb's entry reads each element once and stores the result, so a getter that answers differently on the next read left the check nothing to find. The refusal covered an options bag's named fields and passed over its indices, which is where it pays most: a list element could answer as a trusted signer to the check and as something else afterwards.
- A signer, anchor or policy list whose elements come from its prototype reaches the verb intact. An array resolves a hole through its prototype chain, so `Object.setPrototypeOf(list, {0: signer})` reads as a one-element list to any consumer while reporting no element of its own. The copy taken at the door enumerated only the array's own keys, so the verb received a hole where the caller passed a value: `pki.cms.sign` refused a list it had been given a signer for. Elements at or past `length` are still left out, since no length-bounded read reaches them.
- `pki.key.export(key, { password })` no longer writes an unprotected private key. Export serializes; it has never encrypted. The option was ignored, so the file on disk was a plaintext PKCS#8 while the call site named a password. It now throws `key/bad-input` naming `pki.key.encrypt(key, password)`, whose result is what to export.
- An option carried on a prototype, defined non-enumerably, supplied through a getter, or planted on `Object.prototype` is seen by the check that refuses unknown options. It read own enumerable names only. Each of those four shapes answered `opts.password` while showing the check nothing, and `pki.key.export` returned the private key in the clear, which is the case the refusal exists to prevent. A polluted `Object.prototype` is covered too, where `{}` carries no option of its own; the check reports the planted name and stays silent on the built-ins it was seeded with at load. One thing is still skipped: a method, meaning a data property holding a function that the prototype chain also supplies under that name. So `constructor` and the methods a class defines stay machinery, and an instance of a caller's own class remains a valid options bag whether the verb inspects it directly or after copying it.
- A `Symbol`-named option is reported rather than passed over. The check enumerated with `Object.getOwnPropertyNames`, which never returns a Symbol key, so one was accepted in silence. Such a name answers no `opts.password` and reaches no verb, but it is still an option supplied and never read, which is what the refusal is for. The message names it as `Symbol(name)`.
- A name planted on `Object.prototype` before this package loads is reported, whether it holds a value or a function. The built-ins were recognized by reading `Object.prototype` at load, which is the polluted runtime answering the question, so a name already present was taken for one and `pki.key.export` returned a plaintext private key. They are now the twelve members the language specifies, each still required to have the shape a real one has. The level they are looked for at is the last one an object's chain reaches, which is where the root sits in every realm, so a bag built in a `vm` context or a worker thread is read the same way as a local one. A verb called with no options is unaffected, since it is handed a bag with no prototype and inherits nothing.
- `pki.path.build` forwards the caller's own value for a validation option even on a runtime whose `Object.prototype` carries the same name. It chose what to forward by reading a build-only table with the option name, which answers for any inherited name, so a caller's own `softFail` was taken for a build-only option and dropped; the set it was dropped from then re-read the inherited value. A caller who wrote `softFail: false` could receive a valid path built on an undetermined revocation result they had refused to waive.
- A number, a string or a boolean passed where an options bag belongs is refused by the verb rather than raising a `TypeError` about a reflection method the caller never used.
- A value that inherits from `Date`, `Map`, `Set` or `ArrayBuffer` while holding none of one raises the verb's own `<domain>/bad-input` instead of a raw `TypeError`. These kinds were recognized by their prototype. `Object.create(Date.prototype)` carries that whole prototype and holds no instant, so it passed as a Date and the read behind it threw the language's error out of `pki.cms.sign`, `pki.cms.verify`, `pki.x509.sign`, `pki.path.validate` and the argument copy every signing verb makes. The kind is now read off the value itself. That answers the other direction too, since a `Date` or a `Map` built in a `vm` context or a worker thread holds its kind while inheriting from that context's prototypes, and the prototype test called those neither.
- A `Date`'s instant is read from the Date itself, so a class of the caller's can no longer answer with a different one. `getTime` is an ordinary method on `Date.prototype`, and `class T extends Date { getTime() { ... } }` answers it: one that threw left the time guard through the caller's own exception, and one answering afresh on each call made the instant validated and the instant compared two different reads of the same argument. `pki.cms.verify` copies a caller's validation time and trust-anchor dates the same way, so the policy checked and the policy applied hold one value.
- A byte view's bytes are read from the view itself, so a class of the caller's can no longer say where they are. `buffer`, `byteOffset` and `byteLength` are accessors on the shared typed-array prototype, and `class Opts extends Uint8Array { get buffer() { return elsewhere; } }` answers all three. One that lied substituted the memory: an array holding `AA AA AA AA` whose `buffer` returned another store had every byte door hand back that other store's bytes, so what a verb went on to hash, sign or parse was not what was in the array it was given. One that threw left those doors through the caller's own exception. `pki.webcrypto.getRandomValues` measured its 64 KiB ceiling the same way, and a subclass reporting `byteLength` of 0 passed the ceiling while the fill wrote the array's real length. It also takes a view over a `SharedArrayBuffer` again, which is a supported W3C argument the platform fills: the refusal of shared memory answers a question about input, where bytes another thread can rewrite after they have been checked cannot be checked at all, and a write target the caller chose is the other direction.
- A copied argument comes back as a plain one of its kind, so a verb reading it can no longer be sent into the caller's own code. The copy used to be given the original's prototype back, which left it dispatching there: `list.map(...)` inside a signing verb reached an override on an `Array` subclass, `getUTCFullYear()` reached one on a `Date` subclass, and an override that threw surfaced the caller's exception from inside a verb whose contract is a typed error. A prototype can also be rewritten after the call has begun, so a copy taken to stop the argument changing under the verb changed with it. An instance of a caller's own class copies to a plain object the same way, and a dictionary with no prototype keeps having none, since a copy that gained `Object.prototype` would inherit whatever a runtime has planted there. The names the copy reports are unchanged, which is what restoring the prototype had been for.
- Copying a caller's argument keeps the kind and the instant the value itself holds. The copy chose a byte view's kind through `v.constructor` and its element width through `v.BYTES_PER_ELEMENT`, and took a `Date`'s instant through `getTime`: all three are ordinary properties a subclass answers, so one that threw took the copy out through the caller's own exception, and one that lied produced a copy of a different kind, a different element count, or a different instant than the value being copied. Which kinds those are is taken from the runtime rather than listed, so a typed array of a kind the language adds is copied as itself from the day the runtime names it, and a view of a kind the runtime does not name is refused rather than built through whatever the value says its constructor is. Reading an array element is typed the same way reading a named field already was, so an accessor at an index no longer leaves the copy through its author's own exception while the identical getter under a name raises `<domain>/bad-input`. A `Map` or a `Set` is walked with the language's own `forEach` for the same reason, and the refusal for a value whose state cannot be copied names the kind from what the value is, so a `constructor` that throws no longer replaces the message that says why it was refused.
- A response-body size cap counts the bytes the body holds. `pki.est` and `pki.acme` take an injectable transport, so the response is a value their caller supplies, and `length` on a Buffer is shadowable by an own property: one reporting 0 carried a body of any size past the cap that exists to bound it (RFC 7030 sec. 6). `pki.est.challengePasswordFromTlsUnique` read its emptiness test the same way, and refused channel-binding bytes that were there.
- Bytes built in a `vm` context or a worker thread are taken as bytes. The doors deciding whether an argument is a byte container measured it against this realm's `Uint8Array` and `ArrayBuffer`, so a buffer from another context was turned away; at a door that also accepts a parsed structure it was then refused as a rebuilt one, which reads as a complaint about the certificate rather than about the container it arrived in. The four accepted forms are decided in one place now, from what the value holds.
- An options bag built over a built-in's prototype, or built in another realm, reads the same before and after a verb copies it. Two walks answered the question of which names a caller supplied, and they disagreed. The copy stopped only at this realm's `Object.prototype`, so a foreign bag had its `__proto__` accessor copied down as a supplied name; and away from a collection it read every level of the chain, so `Object.create(Array.prototype)` gained `length` and `Symbol.unscopables`. Either way a bag the check had just accepted was refused once it had been copied. One walk now answers for both.
- The options a verb reads are the options that were checked. Every one is read once as the verb receives them, and the names are taken again afterwards. Checking the names and reading them were two separate moments before, and a caller's getter sits between: `{ get format() { this.password = "pw"; return "der"; } }` showed only `format` while the check ran and grew `password` when the verb read `format`, so `pki.key.export` accepted it and returned a private key in the clear. An option supplied through a getter is therefore refused, and the message names it. A getter answers afresh every time it is read, so the value the check saw says nothing about the one the verb goes on to use, and a name checked once can be joined by another the next time it runs. That covers the getter on the object, the one a caller's class supplies, and the one that waits several reads before adding anything. A class that defines methods is untouched: a method is machinery, not an option.
- A name planted on `Array.prototype`, `Map.prototype` or another collection's prototype is reported. Those levels were passed over whole as the kind's own, so on a runtime carrying `Array.prototype.password` an empty array answered `opts.password` while the check saw nothing, and `pki.key.export` returned an unprotected private key for it. `Object.prototype` was already read for this reason. Every level is read the same way now, and what a kind puts on its prototype is passed over by name, and only where the member is still shaped the way the language leaves it, so a planted value borrowing one of those names is reported too. The names passed over are the ones that kind defines and none a neighboring kind defines: a weak collection counts nothing and has no `size`, a `SharedArrayBuffer` is `growable` where an `ArrayBuffer` is `resizable` and `detached`, and a `DataView` reads its bytes through methods, so it has no elements and no `length` and both are ordinary options on one. Naming the members rather than holding this realm's prototypes also settles a bag built in a `vm` context or a worker thread, whose prototypes are that realm's.
- An option carried on the prototype of an array, a byte view, a Map, a Set or an ArrayBuffer is seen. The check read only such a bag's own names, on the grounds that these kinds carry `buffer`, `byteLength`, `size` and the like on their prototypes and reporting those would refuse a shape the toolkit supports. `Object.setPrototypeOf([], { password: "pw" })` has none of that in its chain and still answers `opts.password`, and `pki.key.export` returned a plaintext private key for it. The chain is now read, with only the levels that describe a kind passed over, so a subclass's own additions are reported too. Copying such a bag keeps its class, so a verb handed the copy reads the same names off it that the check read off the original.
- A byte view whose class overrides `length` reports it as the option it is. `length` is structure only where the language puts it on the value itself: an array carries an own one that no prototype can shadow, while a byte view carries a prototype accessor, so `class Opts extends Uint8Array { get length() {} }` answers `opts.length` with what its author wrote. The name was passed over for every indexed kind, which hid that one.
- A property on an array whose name merely looks numeric is treated as the ordinary named property it is. `"-1"`, `"1.5"`, `"NaN"`, `"Infinity"` and `"4294967295"` are not array indices, and taking them for structure meant an unknown option under one of those names was accepted in silence and dropped from the copy the verb was given.
- An array argument costs what it holds rather than what it measures. Copying walked from zero to `length`, so an array with a high index or an assigned `length` did that many iterations for however few elements it carried.
- Copying a caller's argument no longer drops a name they added to it. A `Date` came back as its instant alone, and an own `constructor` field was skipped along with the inherited one a class defines, so in both cases the copy held nothing while the original still answered and the checks read the copy.
- A `Proxy` whose `getPrototypeOf` trap throws is refused with the verb's own `<domain>/bad-input` rather than the trap's raw error. Reading a prototype chain runs that trap, and the chain was read before the value was recognized as a `Proxy` at all, so the caller's own exception escaped a boundary whose contract is a typed error. Every question about the chain now comes after that decision, at all three doors: the copy path, the one that reports an object's option names, and the one a verb normalizes its options argument at, where the chain was walked by the test for a Buffer in the options position. The kind of an options argument is read off the value itself and never off its type tag, so a caller's `Symbol.toStringTag` is not consulted: a getter under it cannot run, and writing `Arguments` there names nothing. Whether the argument is a `Buffer` is settled by walking its prototype chain rather than by `Buffer.isBuffer`, which is an `instanceof` against an ordinary extensible function: a `Symbol.hasInstance` planted on `Buffer` decided that question, and could answer it by throwing.
- A `Proxy` is refused as an options bag, and as any argument these verbs copy. It answers `ownKeys` and `get` from two independent traps, so one reporting no keys while returning a value for `password` presents an object every enumeration calls empty and every read calls populated. `pki.key.export` accepted such a bag and returned a plaintext private key, which is the case the refusal exists to prevent, and a copy of one silently held nothing the caller had supplied. No enumeration can close that, since it reads only what a trap chooses to say, so the shape is refused by identity rather than probed for a contradiction.
- An argument whose prototype chain is a cycle no longer hangs the call or raises an untyped `RangeError`. A Proxy may report itself as its own prototype while its target stays extensible. Reading an object's option names, copying it, and any `instanceof` inside the copy all walk that chain, and none of them terminated. Reading the names now stops once it revisits an object, which loses nothing since a second lap finds no new name, and copying refuses the shape with the caller's own `<domain>/bad-input` code.
- At every verb named here, an options argument of `false`, `0`, `""` or `NaN` is refused rather than read as no options at all. Verbs outside that list still read a falsy options argument as though none were given, and are a later cut. The check that an options argument is an object ran after the argument had already been replaced by an empty object, and that replacement treated any falsy value as absent, so those four reached the body as `{}`. `pki.cms.sign`, `pki.cms.countersign` and `pki.cms.verify` carried this before this release; the verbs gaining option checks here would have inherited it. `null` and `undefined` still mean no options, and a Buffer in the options position is now named as the argument-order mistake it is. The boxed forms go the same way: `new Number(0)` and `new Boolean(false)` carry no option of their own, so they passed as a bag holding nothing, which is the same silence one wrapper away. A boxed primitive, an `Error`, a `Promise` and an `arguments` object are each refused by name, so the message says which argument was passed rather than naming a field of the engine's own.

## v0.5.10 — 2026-08-18

The documentation and the package's own source comments settle on one spelling of the words they use in both, and a gate keeps them there.

### Added

- `npm run check:spelling` reports any word in the repository that has a second accepted spelling. It runs in `npm run gates`, on every pull request, and again before the published tarball is packed. The check is whole-word and case-insensitive, both to avoid a failure mode: a substring match reports `publicEncrypt` as a misspelling, and a case-sensitive one walks past the same word capitalized or upper-cased. It self-tests on planted forms before reporting, so a word list that has stopped matching cannot pass as a clean tree.

### Changed

- Documentation and source comments now use the US spellings behavior, recognize, unrecognized, labeled, honored, license, defense, neighbor, authorize, initialization, enrollment, signaled, modeled, favor and fulfill. 267 occurrences across 98 files no longer carry a second spelling: the README, the security policy, thirteen release notes and the changelog generated from them, the status-lifecycle record, the comments and error text in lib/, the test suite, and the release and wiki tooling. That figure counts words whose spelling changed, so a line edited for another reason that happened to contain one of these words is not counted twice. One word settles the other way: catalogue, which this repository already used by 185 uses to 32, so the checked form is that one and the US spelling is what now reports. Simple Certificate Enrolment Protocol is RFC 8894's title, quoted as published and allowed only on a line carrying that title in full, so the exception cannot spread to the word.

## v0.5.9 — 2026-08-17

A certificate can now carry an internationalized email address, which this toolkit could read and never write.

### Added

- pki.x509.sign accepts an otherName entry in a subjectAltName, given as { typeId, value } where typeId is an OID string and value is a Buffer holding one DER element. It encodes RFC 5280 section 4.2.1.6's otherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }, tagged [0] IMPLICIT. The value wrapper is EXPLICIT because ANY carries no tag of its own, which is what makes the encoding unambiguous and is the shape the decoder already required. This is what an SmtpUTF8Mailbox address needs, and it is equally the carrier for any other otherName a profile defines.
- The value is validated before it is wrapped and signed, because a signer that emits a malformed encoding under a real signature has produced something strict relying parties reject. It must be exactly one element with no trailing bytes, and its contents must satisfy the rules for its type: a BOOLEAN whose octet is not 0x00 or 0xFF is refused, as is a SET whose members sit in no canonical order, and so on recursively through a constructed value. The accepted universal types are BOOLEAN, INTEGER, ENUMERATED, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER, UTCTime, GeneralizedTime, NumericString, and the DirectoryString family (UTF8String, PrintableString, IA5String, TeletexString, VisibleString, BMPString, UniversalString), plus SEQUENCE and SET. A universal type outside that set, such as REAL or RELATIVE-OID, has no content validator here and is refused rather than accepted on its framing alone. A context- or application-tagged value passes on its framing, since no content rule is knowable for it, and its children are still walked. One known limitation: a GeneralizedTime carrying fractional seconds, such as 20260101000000.5Z, is refused here even though X.690 section 11.7 permits it. That relaxation is scoped to the codec and to RFC 3161 timestamping on purpose, and this validator does not widen it. A constructed wrapper does not evade the rule, since the walk recurses into its children; a profile needing a fractional time must carry it under an implicit primitive context tag, which passes on framing because no content rule is knowable for it.

### Fixed

- pki.smime.verify's sender binding is now exercised against certificates carrying an otherName. Two behaviors that previously had no conformance vector are pinned: a certificate whose subjectAltName carries an SmtpUTF8Mailbox does not let a legacy subject distinguished-name emailAddress speak for it, and an otherName unrelated to email, such as a Microsoft user principal name, neither erases a matching rfc822Name nor turns a definite non-match into an undecidable one.

## v0.5.8 — 2026-08-17

Four verdicts that answered a question nobody had asked now say what they checked, and an email domain comparison no longer folds two registrable domains into one identity.

### Added

- pki.cms.decrypt reports originAuthenticated, authenticatedBy and originatorInfo. authenticated is a claim about the content and the key that opened it; it never described who sent the message. originAuthenticated is false for every recipient type the toolkit supports: a ktri or ephemeral-static kari message is minted by anyone holding the recipient's public key, and a pwri or kekri message by any co-recipient sharing the secret. authenticatedBy names what the integrity rests on. originatorInfo is now surfaced rather than decoded and discarded, and is documented as unauthenticated: it sits outside the AEAD's authenticated data, so it is a hint the sender chose, and any certificate it carries must be validated before use. To bind a sender, verify a signature over the plaintext.
- pki.smime.verify accepts expectedSender and reports a sender block of { checked, expected, source, identities, match }. A signature proves a key signed; it does not prove the message came from the mailbox the reader sees. match is true only when the signer certificate asserts the address, compared under RFC 5280 section 7.5: the local-part exactly, the host-part case-insensitively. The address is read from the subjectAltName rfc822Name entries (RFC 8550 section 4.4.3), and where the extension carries none, from the subject distinguished name's PKCS #9 emailAddress attribute, which RFC 8550 section 3 requires a receiving agent to recognize. Where both are present the extension is authoritative, so a stale subject value cannot satisfy expectedSender while the extension names a different mailbox. It is three-valued: false when every identity was comparable and none matched, null when the question went unanswered, and null is not a pass, so a caller enforcing sender binding tests match === true. identities lists what the certificate actually asserts. With no expectedSender a single outer From is used and reported as source: "from", which is advisory, because on a message without header protection that header is attacker-controlled.

### Changed

- pki.smime.verify's headerProtection.fromMismatch is now null when there was no protected From to compare against, where it was previously false. It reported false on every message without RFC 9788 header protection, which is nearly all mail, so testing not fromMismatch read as a passed sender check on messages where no comparison had run. It is now true when the outer From differs from the protected one, false when they agree, and null when nothing was compared. null is falsy, so an existing not fromMismatch test keeps working and keeps accepting the unchecked case: compare against false explicitly. For a sender binding that does not depend on the composer having protected the headers, use expectedSender and test sender.match === true. See MIGRATING.md.

### Fixed

- An rfc822Name identity comparison no longer folds the host-part with a Unicode-aware lowercase. U+212A KELVIN SIGN lowercases to ASCII k, so ban<U+212A>.com and bank.com are different byte strings, separately registrable, that compared equal and read as one email identity. The host-part is now folded across A-Z only, which is the case-insensitive ASCII comparison RFC 5280 section 7.5 authorizes and no more. The local-part was already compared exactly and stays that way: RFC 8398 section 5 requires that it not be transformed in any way, including by case folding.
- pki.merkle.verifyConsistency refuses a proof whose older tree is empty and whose newer tree is not, as merkle/no-consistency-claim. RFC 6962 section 2.1.2 defines a consistency proof for 0 < oldSize < newSize. An empty tree is a prefix of every tree by definition, so there was no proof to check and nothing bound the newRoot that was passed: any value returned true, including a root from a different log. Two empty trees are unchanged and still check each root against the empty root hash.
- pki.cmc.verify refuses a Full PKI Response that carries nothing tying it to a request, as cmc/unbound-response. Every binding the module could check was previously conditional on the caller having supplied the matching value, and nothing in the verdict reported whether any of them ran, so a response captured from an earlier successful enrollment against the same CA verified identically. Pass what the request retained (transactionId, senderNonce, whose echo is the replay defense of RFC 5272 section 6.6, or dataReturn), or allowUnbound: true to interpret a response that could be a replay of any earlier exchange.

## v0.5.7 — 2026-08-16

A CMS signature made over signed attributes can no longer be re-presented as one made over content.

### Added

- The pki.cms.verify verdict carries eContentType, and each signers[i] carries signedAttributesPresent. Signing with attributes and signing the content directly are different claims: attributes bind a content type and a signing time alongside the digest, while content-only binds nothing but the bytes. One message may carry a signer of each. A caller whose profile is stricter than RFC 5652's, such as RFC 8551 S/MIME which requires signed attributes, can now enforce that from the verdict instead of parsing the message a second time. A check that needs a second parse is a check most callers will not write.

### Changed

- Because the producing verbs now copy their arguments at entry, each property of a spec or options object, own or inherited, is read exactly once, when the verb is called. A field defined as a getter is therefore evaluated at that point even if the verb has no use for it, and a getter that throws surfaces as that module's bad-input fault before its own validation of any other field. Reading each property once is deliberate: a getter consulted twice can answer differently the second time, which is the same problem the copy exists to remove. Plain data specs are unaffected.
- One argument shape cannot be copied and is refused: an object whose state this toolkit cannot read (a WeakMap or WeakSet, a promise, a CryptoKey) carrying its own named fields alongside. There is no safe handling for it, because it cannot be copied and passing it through would leave those fields changeable after the checks had read them, so it fails with the module's bad-input code and says to pass the fields as a plain object. The same objects are accepted as before when they carry only what their kind defines, which is what a real key, a real promise and a real WeakMap do.
- SECURITY.md previously said an attacker could "neither swap the content out from under a set of signed attributes, nor strip the attributes and present a signature made over them as one made over the content". The first half was true; the second was not, and had not been since the claim was written. The entry now describes what is actually defended and how, and names the case it costs: content which genuinely is an encoded SignedAttributes block must be signed with signed attributes. The v0.5.6 notes described the parsed-object re-derivation as closing this forgery; it closed the half reachable through a caller-assembled object, and this release closes the half reachable from bytes.

### Fixed

- pki.cms.verify refuses a SignerInfo with no signed attributes whose content is itself an encoded SignedAttributes block, as cms/ambiguous-content. This is Attack Type 1 of draft-vangeest-lamps-cms-euf-cma-signeddata: take a message signed with attributes present, drop the signedAttrs field, set the encapsulated content to the DER of those attributes, keep the signature. The signature genuinely verifies over those bytes. What is refused is the shape, which is why it has its own code and does not read as cms/bad-signature. The condition is necessary to the attack; it is no guess at anything SET OF shaped: RFC 5652 section 5.3 requires signed attributes to carry both a content-type and a message-digest attribute, so every message the attack produces has content carrying both, and content that is a set of attributes missing either one is not refused. Ordinary content (a certificate, a JSON payload, arbitrary bytes) does not have the shape at all. Verified against the shipped verb before and after, and the standards fixes for this are protocol changes (signing under a context string that names the mode) which no verifier can apply on its own.
- pki.cms.sign refuses to sign content that is itself an encoded SignedAttributes block when signedAttributes is false. That is the other direction of the same problem (Attack Type 2): such a signature can afterwards be promoted into an attributes-present message, because the signature does not commit to which mode was used: the attacker attaches the signed bytes as the SignedAttributes and swaps in whatever content their message-digest attribute names. Refusing to mint the ambiguous signature is the only point at which that direction can be stopped. Sign the same content with signed attributes and it is unambiguous again.
- A byte argument whose backing store has been transferred away is refused instead of read as empty. Transferring an ArrayBuffer (a structuredClone with transfer, a worker hand-off, a stream that adopts the buffer) leaves every view of it reading zero-length, with no throw, so a boundary that passed the caller's object straight on operated on nothing and succeeded: pki.cms.sign produced a sound, verifiable signature covering no content at all, pki.cms.compress the same, and pki.pkcs12.build derived its MAC and encryption keys from the empty password. Every boundary that takes caller bytes now re-views the input first and refuses a detached one with that module's own bad-input code. Where the empty read already failed further down, as when an empty certificate does not parse or an empty private key does not import, the refusal now carries the calling module's code and names the argument; it no longer surfaces whatever the later failure raised.
- A producing verb reads its arguments once, at entry. Every one of them does work across more than one promise turn, so a caller still holding a spec, an options object or a signer could change a field after the call returned and have a later turn read the new value: the checks ran against one input and the artifact was built from another. Every argument of pki.cms.sign, pki.cms.countersign, pki.x509.sign, pki.csr.sign, pki.crl.sign, pki.attrcert.sign, pki.crmf.build, pki.cmc.build, pki.cmp.build, pki.ocsp.buildRequest, pki.ocsp.sign, pki.tsp.sign and pki.pkcs12.build is now copied whole at entry, at every depth, and each copy is cleared when the call settles. Reachable cases included flipping signedAttributes from true to false to skip the content check the entry above describes, rewriting a certificate's key identifier or a CRL's authority key identifier between the check and the encoding, changing the encoding pki.x509.sign returns after the signature came back, rewriting the PKCS#12 password partway through so the file's MAC and its bag encryption were keyed to two different values, and rewriting the nested pki.cmp.build MAC secret so the message went out authenticated under a value the caller never supplied. Copying at one level does not cover the last of those and copying without clearing duplicates the secret, so both halves are the rule. A parsed structure passed inside a spec keeps its identity, so it still satisfies the verbs that require parser provenance, and a CryptoKey is used as it stands, never cloned.
- The verbs documented as returning a Promise now run their body at the call, and no longer a turn later. Ten of them deferred everything, including reading the caller's arguments, until after the call had already returned, which left the window above open even for a verb that copies its input on the first line. They still report a fault by rejecting and never by throwing; only the timing of the work changed.

## v0.5.6 — 2026-08-15

A CMS SignedData is verified over the bytes it was parsed from, an omitted PKCS#12 password is refused and never encoded as the empty one, and a verb documented as returning a Promise rejects instead of throwing past your .catch.

### Changed

- A verb documented as returning a Promise now rejects; it never throws synchronously. An operator reads -> Promise<...> in the reference and writes the documented shape, pki.cms.sign(content, signers).catch(handleIt). A validation that ran before the promise was created threw straight past that .catch, so a misspelled option or a malformed input became an uncaught exception in code that already handles errors. Nothing in the shape of the call said which verbs did it. Eleven did: pki.cms.verify, pki.cms.sign, pki.cms.countersign, pki.ocsp.sign, pki.tsp.sign, and six pki.acme verbs. Nine more on the client pki.acme.client(...) returns did the same, including getAuthorization, which an ordinary ACME loop reaches with a URL that came from the CA. The checks still run synchronously, so a caller's mutable options are read before any turn passes; only the way a fault leaves has changed. If you wrapped one of these verbs in a synchronous try/catch without awaiting it (the documented signature never supported that, though it worked by accident on exactly these verbs), that catch no longer fires and the rejection surfaces as an unhandled one instead. Await the call, or attach .catch to it.
- pki.tsp.verify reports whether revocation was established, as well as whether the timestamp authority chained. Revocation runs only when a revocationChecker is supplied, so a token whose TSA was never checked against a CRL or an OCSP responder read identically to one established un-revoked, and that is the default. The verdict now carries revocationChecked and anchorConstraints from the path validation, in pki.path.validate's own vocabulary, so a timestamp archived to be re-read years later can still answer what was actually checked. The trustAnchor documentation no longer lists revocation unconditionally.

### Fixed

- pki.cms.verify computes its verdict over the bytes the parser read. A SignedData's meaning is a signature over a byte range, but a parsed one presents that range, the signature, the algorithms and the certificates as separate properties, and the verb read them as though the parser had produced them together. The forgery that follows is concrete: take a message a trusted signer really signed, keep its SignerInfo and signature untouched, set signedAttrsBytes to null, and present the signature's own preimage (the signed attributes re-tagged as the SET OF the signature covers) as the encapsulated content under any content type you like. With no signed attributes the signature is checked against the content directly, which is exactly those bytes, and neither the content-type nor the message-digest check runs, so the message verifies as valid content the signer never signed. pki.schema.cms.parse now records what it read, pki.cms.verify re-derives from that record, and a SignedData the caller built by hand is refused with a typed error, where it used to be dereferenced into a raw TypeError. Passing DER, PEM, or the parser's own unmodified result is unaffected.
- pki.pkcs12.build refuses a store with no password; it no longer builds one under the empty password. An omitted password and the empty password are different credentials, and the difference was invisible at the call site: pki.pkcs12.build(spec) with no options at all, or with the option name misspelled, returned a well-formed store whose shrouded private key opened under "": a key protected by nothing, with no error anywhere. The empty password is still available; it has to be asked for, as "".
- pki.pkcs12.build validates opts.integrity.mode against the value it accepts. Compared against a single literal, any other spelling read as "not public-key" and silently selected password integrity, dropping the signer with it: a caller who wrote mode: 'publicKey' asked for a CMS signature over the AuthenticatedSafe and got a password MAC. Combined with the previous item, a caller who misspelled both options got a store MACed under the empty password while believing it was signature-protected. An unrecognized key on opts.integrity is refused too.
- pki.pkcs12.open bounds the key-derivation work of a modern store as well as a legacy one. The aggregate budget existed because a per-bag iteration cap resets on every bag, so a store that repeats a costly bag up to the parser's element limit multiplies the cap by that limit. It was charged only on the RFC 7292 Appendix C path, leaving the RFC 8018 PBES2 path free to do exactly that: the path OpenSSL and NSS emit, and the one this toolkit itself builds. Measured before the fix: ten bags at a million iterations each ran ten million aggregate rounds of blocking PBKDF2 with no refusal. Both schemes now charge one budget, and it is charged before the derivation runs, no longer after.
- A PKCS#12 password this toolkit encoded is cleared once the derivation has consumed it, on the PBES2 and PBMAC1 paths as well as the classic ones. The Appendix B.1 copy taken from a password argument was wiped while the UTF-8 copy taken from the same argument in the same call was not, leaving a plaintext password in the heap after every modern bag encryption, bag decryption and MAC. A Buffer you supply is never written to: it is yours, and clearing it would destroy your credential, which is the thing being protected.
- pki.tsp.request validates a pre-encoded extension instead of splicing it in. Elements of opts.extensions were checked only for being byte-like and then concatenated straight into the request, so a caller relaying an extension blob it did not author put fully chosen bytes into the structure. The encoder emitted requests its own pki.tsp.parseRequest refuses: an undecodable value, a repeated extension identifier, an explicit critical=FALSE that DER requires be omitted. Each element now goes through the same pre-encoded-Extension gate every other request builder in the toolkit applies, including the duplicate-identifier check.
- pki.tsp.sign, pki.tsp.request and pki.tsp.verify report a bad serial number or nonce as a typed tsp/bad-input. A value that is not an integer reached BigInt() directly and raised a raw SyntaxError or RangeError out of a public verb, an untyped fault a caller handling tsp/* codes cannot catch.
- pki.sigstore.verifyBundle refuses an option it does not recognize. The identity policy one level down already did, for the reason that applies just as much at the top: the signer pin goes by other names in other Sigstore tooling, and a spelling this verb swallowed checked nothing under a name the operator believed pinned the signer. At the top level the same slip also loses the SLSA predicate pin, and unlike the identity fields there is no report field to reveal it: the verdict said verified: true with the signer and the predicate entirely unpinned.

## v0.5.5 — 2026-08-15

A verdict is computed over the bytes the parser read, an identity is derived from the bytes that carry it, and the guards match no patterns.

### Changed

- The package resolves one entry point. require("@blamejs/pki") is unchanged; a path into the package, such as require("@blamejs/pki/lib/schema-x509"), no longer resolves. Every module under lib/ carries @internal in its own header and none has ever appeared in the API snapshot that freezes the public surface. They were reachable only because the package declared no exports map, and one of them mints the provenance record the integrity verbs above rely on. Everything the internals do is on pki.*: the decoders are pki.schema.<format>.parse, the codec is pki.asn1, the OID registry is pki.oid, the error classes are pki.errors. MIGRATING.md carries the recipe.
- pki.merkle, pki.jose, pki.hpke, pki.smime and pki.est refuse an option they do not recognize, which completes the toolkit: every module that takes options now does. A misspelled option is the one input that reads as an omission, so the caller who asked for something stricter gets the looser default and is told nothing: a misspelled psk leaves an HPKE psk-mode setup with no pre-shared key, a misspelled key leaves pki.jose.verify accepting whichever key the message names, a misspelled leafIndex leaves a Merkle inclusion proof about a leaf the caller never chose, a misspelled strictMicalg accepts the S/MIME digest mismatch it was set to reject, and a misspelled expectedRecipientKeyId drops the recipient pin on an EST server-generated private key. The accepted set is per verb, since the surfaces differ even inside one module: form means something to pki.smime.sign and nothing to pki.smime.encrypt, strict cannot run on pki.est.cacerts at all, and HPKE's two ends read the same object from opposite sides, so senderPublicKey does nothing at the sender and senderKey nothing at the recipient. A merged set would accept each verb's options everywhere and reproduce the silence in a wider form, which is why an option passed to the wrong end of an HPKE exchange is refused with a message saying where it belongs, because the caller who passed it usually believes they authenticated something. Four options pki.smime.sign has always forwarded (hcp, sid, signedAttributes, additionalSignedAttributes) and EST's auth object are now documented; they worked before and were absent from the reference.
- The guards match no patterns. A guard runs on the most hostile input the toolkit sees, and a pattern engine's cost on a rejecting string is a property of the pattern, which is the one thing a caller's size cap cannot bound. Nine patterns across five guards are now explicit character walks, each one pass. Three carried a second defect settled by the rewrite: the whitespace fold above, a JSON number grammar written twice (once as the scan and once as a pattern re-matching what the scan had just read), and an RFC 4514 escape that ran a pattern replace and then a second loop over the same attacker-supplied value.

### Fixed

- A claimed-parsed structure must carry every field the matching pki.schema parser produces. The rule already existed at one door: pki.path.build refused a partial claimed-parsed certificate. pki.path.validate, which build hands its result to, tested only for a truthy tbsBytes and passed the object into the RFC 5280 sec. 6.1 walk. Eleven doors now share it: pki.path.validate and build, pki.path.crlChecker, pki.crl.verify / isRevoked and the issuer of pki.crl.sign, the issuer of pki.x509.sign, pki.attrcert.sign, pki.ocsp's certificate argument, pki.lint, and the caller root certificates pki.webauthn takes for attestation and for android-safetynet. Completeness is measured against the parser. What any one verb happens to read is too narrow a bar, because a field absent from an object is not a field with a safe default: an extension entry with no critical property read as non-critical, so a certificate rejected for an unknown critical extension when passed as bytes validated when passed as an object; a missing serialNumber surfaced as an error from the ASN.1 layer; and a missing issuer.bytes produced an OCSP request whose issuerNameHash covered nothing. Passing bytes, PEM, or the parser's own unmodified output is unaffected.
- A certificate or CRL a verdict is taken from is re-derived from the bytes its parser read. pki.path.validate and build, pki.path.crlChecker, pki.crl.verify and pki.crl.isRevoked all reach a decision, and completeness alone cannot carry one: a certificate is one signature over one byte range, but a parsed certificate presents that range, the signature, and every field the range encodes as separate properties. Keep a real CA certificate's signed bytes and signature and replace only its subjectPublicKeyInfo, and every field is well-formed, the signature verifies over the original range, and the substituted key is then what verifies the next certificate in the chain: a forged chain built out of a genuine certificate. Emptying extensions is the same move against basicConstraints, keyUsage, name constraints and the unknown-critical rule; emptying a CRL's revokedCertificates leaves a correctly signed CRL reporting a revoked certificate as good. pki.schema.x509.parse and pki.schema.crl.parse now record what they read, these verbs parse it again from that record, and a certificate or CRL the caller assembled, with no parse behind it, is refused. Passing bytes, PEM, or the parser's own unmodified output is unaffected.
- pki.ocsp.verify, pki.path.verifyOcspResponse, pki.pkcs12.verifyMac and pki.pkcs12.open compute their verdict over the bytes the parser read. A signature check has three parts: the signature, the algorithm that verifies it, and the byte range it covers. On a parsed response all three are separate properties: pair a real CA's signature over a certificate that CA issued with that certificate's own signed bytes and algorithm, relabel the three, and every part of the check passes for a response the responder never produced. A PKCS#12 store has the same shape with two parts, the range the MAC covers and the bags handed back as verified, so one object could say verify this and return that. The parsers now record what they parsed and these verbs re-derive from that record, so an object edited or rebuilt after parsing is not what the verdict describes. Passing the parser's own result still works and is unchanged.
- pki.attrcert.sign derives both halves of a Holder's identity from the signed bytes. Issuer and serial together are the identity being bound; the issuer was decoded from tbsBytes while the serial was read off the object, so a parsed certificate with one field replaced produced a Holder naming a real issuer with a serial nobody issued.
- pki.trust.anchor answers from what the store read. A root program's metadata (these purposes, until this date) is a statement about a key, so an entry rebuilt with a substituted publicKey carried the program's word onto a key it never saw; the (name, key) pair is now re-derived from the certificate the store parsed, and an entry carrying store metadata without that provenance is refused. The purposes and distrust dates come from the same place and are copied on the way out, so neither editing a store entry nor writing through a returned anchor changes what that anchor authorizes: pki.trust.anchor(entry).purposes.serverAuth = true no longer opens a gate the store never opened, and an anchor reports the store's bits and dates however the caller has since handled the entry. A caller asserting their own bare (name, key) anchor carries no metadata and is unaffected.
- A private key decoded for the crypto engine is wiped once the engine has imported it. A signer or recipient key may be given as a Buffer, a Uint8Array, or a PEM string; the first is the caller's own memory and is used in place, while the other two are decoded into a new buffer inside the toolkit. That is a second copy of a private key, and until now it stayed readable in the heap until the garbage collector happened to reuse the page. It is cleared on the failure path too, so a malformed key or a tampered message is not a way to leave one behind. A Buffer you supply is never written to: it is yours, you still hold it, and clearing it would destroy the key we are supposed to be protecting.
- pki.webauthn.verifyAssertion holds both accepted forms of a stored credential key to the same rules. The COSE bytes went through the curve and length rules, the 2048-bit RSA modulus floor and the exponent checks; the object form went through none, so one key was refused in one form and imported for signature verification in the other. Which form a relying party stores is a question about what their datastore round-trips, and no longer a question about how carefully their credential is checked.
- A certificate's keyUsage is read the same way at every boundary that asks what the certificate may do. keyUsage is a NamedBitList, so DER drops its trailing zero bits (X.690 sec. 11.2.2) and RFC 5280 sec. 4.2.1.3 requires at least one bit set. Four boundaries read the bits themselves and applied neither rule, so one certificate could be authorized in one place and called malformed everywhere else: pki.crl.verify accepting a CRL signer, pki.tsp.verify accepting a timestamp authority, pki.cms.encrypt accepting a recipient, and the FIDO metadata reader accepting the leaf that signs a catalogue.
- The distinguished-name comparison that decides name chaining, revocation-issuer matching and name constraints folds the four ASCII whitespace characters X.520's caseIgnoreMatch names, and no others. It had been collapsing whitespace with a pattern, which also folds vertical tab, form feed, no-break space and every Unicode space separator, equating names X.520 keeps distinct.

## v0.5.4 — 2026-08-15

A path verdict says whether revocation was ever established, a trust anchor's own distrust metadata can no longer sit inert, and a CRL is asked what only a certificate can answer.

### Added

- pki.path.validate reports revocationChecked, taking the weakest outcome on the path: false when no revocationChecker was supplied, "determined" when every certificate got an explicit good or revoked answer, "waived" when softFail turned an undetermined one into a pass, and "undetermined" when one could not be answered at all. The per-certificate revocation check carries the status it was decided on and marks a waiver, so "checked, and it said good" is distinguishable from "could not check, and you waived it". Those were the same object before, which is why a stored verdict could not answer whether revocation was ever established.
- pki.path.validate reports anchorConstraints: the checkedPurpose the anchor's trust metadata was judged under, and whether the distrustAfter date and the purposes delegator map each applied. A bare anchor says it carried nothing to apply; it no longer says nothing at all.
- pki.tsp.verify returns trusted alongside valid. The entire out-of-path TSA certificate validation runs only when a trustAnchor is supplied, so one boolean collapsed "the token's signature and structural bindings hold" with "the timestamp authority is one you accept". A timestamp is archived precisely to be re-read years later, when that distinction is the whole question. Without an anchor trusted is false: a definite answer, on the refusal branch as well as the accepting one.

### Fixed

- A trust anchor carrying purpose-scoped metadata is no longer validated as though it carried none. distrustAfter and purposes are indexed by key purpose, so neither could apply unless the caller passed opts.checkPurpose, an option absent from the verb's own documentation while SECURITY.md described the enforcement as unconditional. An anchor carrying that metadata with no purpose to select by is now a configuration fault (path/bad-input), and no longer a constraint that silently does nothing.
- pki.tsp.verify names the timeStamping purpose when it validates the TSA chain, so an anchor's trust metadata reaches the decision. It already required that key purpose of the TSA certificate; asking the certificate without asking the anchor checked one end of the chain and left the other: a root explicitly distrusted for timestamping still answered trusted.
- A revocation checker that throws, or whose promise rejects, fails the path with path/revocation-checker-error carrying the fault, including under softFail. It was laundered into an unknown status and then waived, so a broken checker and a working one that could not reach the responder produced the same verdict, and a certificate could pass with no revocation result at all. softFail is the caller opting into an undetermined answer, which the built-in CRL and OCSP checkers report as status "unknown" for every unreachable or unverifiable condition; neither throws, so a throw is a fault in the caller's own code, and it surfaces.
- pki.crl.verify asks what only a certificate can answer. Given one, it now also checks that the certificate is the issuer the CRL names and that its keyUsage, when it carries one, asserts cRLSign, the rule this module's signing side already enforced. A signature verifying says only that some key signed these bytes, so a CRL minted under an end-entity certificate of the same CA verified as that CA's CRL. Both answers are false, and neither throws, so trying each candidate issuer in turn still works; handed a bare key there is no certificate to carry either restriction and the signature remains all that is checked.
- pki.crl.isRevoked checks the CRL's scope before looking for the serial. A serial means something only inside the set of certificates a CRL speaks for, and this verb is handed a serial and nothing else. A CRL speaking for part of its issuer's certificates is now refused; it is no longer answered from. A delta CRL lists changes since a base, so an entry recording that a certificate was released reads as a revocation when the delta is read alone (crl/delta-not-authoritative); an indirect CRL carries other issuers' entries, whose serial numbers are unrelated to yours (crl/indirect-not-supported), as does any CRL carrying certificateIssuer on an entry while declaring itself direct, since the contradiction belongs to the list as a whole. Every other issuingDistributionPoint narrows the CRL to one distribution point, one kind of certificate, or a subset of revocation reasons (crl/scope-not-authoritative): which part applies is decided against fields of the certificate, so a serial absent from such a CRL is not a certificate that is unrevoked. Each of these previously answered, and the answer could be the opposite of the truth. pki.path.crlChecker is the verb for all of them: it is handed the certificate, merges a delta with its base, and performs the RFC 5280 sec. 6.3.3 scope correspondence.
- A certificate's keyUsage is read the same way at every boundary that asks what the certificate may do. keyUsage is a NamedBitList, so DER drops its trailing zero bits (X.690 sec. 11.2.2) and RFC 5280 sec. 4.2.1.3 requires at least one bit set. The shared extension decoder enforces both rules, which is why the issuing side and pki.path.validate already applied them. Four boundaries read the bits themselves and applied neither, so one certificate could be authorized here and called malformed everywhere else: pki.crl.verify accepting a CRL signer, pki.tsp.verify accepting a timestamp authority, pki.cms.encrypt accepting a recipient, and the FIDO metadata reader accepting the leaf that signs a catalogue. All four now route through the decoder, so a certificate this toolkit refuses to issue is a certificate it refuses to trust.
- An issuingDistributionPoint scope flag is read under the encoding rules that define it, in both the CRL verbs and the path validator, and no longer by inspecting a content byte. Each flag is an IMPLICIT BOOLEAN, so DER admits exactly one content octet of 0x00 or 0xFF; a byte test read an empty flag as absent and a multi-octet one by whichever byte it indexed, and absent is the reading that lets a CRL whose scope cannot be established answer a serial anyway. Signing rejects a pre-encoded issuingDistributionPoint on the same terms, so this toolkit cannot emit a CRL whose scope a relying party would read differently.

## v0.5.3 — 2026-08-14

pki.webauthn checks the ceremony at registration, withholds a revoked model's anchors, and refuses a name comparison it cannot perform.

### Added

- pki.webauthn.verify accepts opts.clientDataJSON as an alternative to the clientDataHash argument. Supply exactly one of the two; neither is inferred from the other's absence. Given the JSON it reads it: the ceremony type is checked unconditionally, because which ceremony a response belongs to is fixed by the specification and is not the caller's to choose, and a login response replayed into a registration is what that check stops. The challenge, origin and top-level origin are checked against what you issued, and the verdict carries clientData, whose checked field says which comparisons ran. From the digest form clientData is null: nothing read it, and reporting anything else would claim a check that never happened. An expectation supplied without the JSON is refused; it is never left silently uncompared.
- parseClientData, verify and verifyAssertion take expectedTopOrigin: an origin, a list of them, or null to require an unframed ceremony, which a list cannot express. In a cross-origin ceremony origin is the framed document's and topOrigin names the page that framed it, so the framing policy is about the second: a value a relying party could read and nothing could compare. It is compared whole and case-sensitively, as origin already was, and reported in checked alongside it. Whether a ceremony was framed is stated by both crossOrigin and topOrigin and is only usable when they agree, so a response cannot answer the policy with the field it left out.
- A verified FIDO metadata result reports rollbackChecked and the previousNo it was compared against, as it already reported what the freshness rule found. The rollback rule runs only when a caller supplies the sequence number it holds, so a result that recorded nothing could not be told from one where the check was skipped. Being able to show the catalogue never went backwards is the whole point of the rule.
- pki.jose.sigAlgs() lists the JWS signature algorithms this toolkit verifies, one row per alg with the JWK key type, curve, hash and PSS salt length it requires. Each call returns fresh rows; the registry that drives verification is never handed out, so nothing a caller does to the result can widen what a signature check accepts. MAC algorithms are absent by construction: HS256 is not a signature algorithm, and listing it beside RS256 is how the key-confusion class starts.

### Changed

- Every byte argument in pki.webauthn accepts the same forms: a Buffer, any typed-array view, a DataView, or an ArrayBuffer. They differed per argument before, so verify took an attestation object as an ArrayBuffer while refusing a clientDataHash in the form crypto.subtle.digest returns, which is the natural output of the API these verbs exist to serve. The same held for a metadata BLOB, which is retrieved over the network and so most naturally arrives as the ArrayBuffer a fetched body gives you, and for the certificates supplied as trust anchors, where identical DER is the identical certificate whichever container it was read into. Anything that is not bytes is refused by name, where before it was described by whichever parser reached it first.
- opts.requireCtsProfileMatch is refused when the attestation cannot satisfy it. It is a demand about an android-safetynet device-integrity signal and was checked only inside that format's arm, so a relying party that demanded a CTS-matching device got a pass from a packed or none attestation that was never asked the question. That is the same shape the TPM key policy beside it already guarded against. A mistyped requireCtsProfileMatch or verifySafetyNetJws is now a configuration fault whatever the format, and no longer a truthy string that demands nothing.
- pki.webauthn.metadataAnchors takes a second, optional argument carrying the metadata result, the instant to judge at, and the attestation certificate presented.
- The documented signatures of pki.webauthn.verify, verifyAssertion and parseAuthenticatorData list every field their verdicts carry, and verify documents its options.

### Fixed

- The canonical RFC 5280 sec. 7.1 distinguished-name comparison refuses input it cannot compare, instead of answering that it matched. It takes the RDN sequence on both sides; handed a parsed Name object it compared two absent lengths, ran its loop zero times, and returned true for two unrelated names. One caller passed that shape: the FIDO metadata anchor test, whose name half was therefore inert, leaving the public-key comparison to carry a decision RFC 5280 sec. 6.1.1 defines as name and key together. It passes the RDN sequence now, and every other call site in the toolkit already did.
- A metadata entry whose status reports disqualify the model registers no attestation anchors. The route an operator follows to anchor an attestation themselves (metadataFor, then metadataAnchors, then pki.path.validate) never consulted those reports, so a revoked authenticator's registered roots were handed back and the path validated against them. metadataAnchors now refuses with webauthn/metadata-status. An entry may only be judged against the catalogue it was read out of: a process holding two would otherwise be able to pair an entry from one with the other, and the second's status policy and freshness would decide about the first's reports. A by-date reading would hand back anchors the entry's own catalogue records as revoked. It reads the status reports exactly as the attestation path does when given the same three things: the verified catalogue and its status policy, the instant to judge at, and the attestation certificate presented. Where you leave one out it applies the strictest reading: any disqualifying report denies, judged now, with no report treated as concerning some other certificate. Supplying all three, which is what the attestation path does, is what makes the two verdicts identical; supplying none can only refuse more.
- An attestation certificate's public key must match the credential public key in kind as well as in bytes. An X25519 key-agreement key and an Ed25519 signing key are both 32 raw bytes, so on the Edwards curves the material alone cannot separate them. For the apple format, which carries no attestation signature, this comparison is the entire binding. The certificate's declared key algorithm is now part of it for every key type; before, only the EC branch asked, as a curve check.
- An RSA credential key's public exponent must be minimally encoded, as its modulus already had to be. Padded, 00 01 reads as a two-byte exponent and skips the value check that refuses 1, the identity exponent, under which every signature verifies. A padded short modulus could clear the modulus floor the same way.
- An Edwards certificate key is validated on-curve and full-order before a metadata BLOB signature is verified under it. The identity point and the other low-order points are imported by the platform without complaint and verify a trivial signature over any message, so a leaf carrying one authenticates whatever payload it is shown. Chaining to the pinned FIDO root does not help: the certificate is properly issued and still malformed. Every other Edwards key in the toolkit already passed this gate; the metadata reader takes the same one now, through the shared entry, with no second copy of it.
- An id-RSASSA-PSS key's parameters restrict it even where they look empty, in both directions: signing and verification read the restriction through one reader. RFC 4055 sec. 3.1 makes the presence of the parameters the line: absent, they restrict nothing; present, the certificate user must use the hash they identify. hashAlgorithm is [0] ... DEFAULT sha1Identifier, so a parameters SEQUENCE that omits it names SHA-1; it does not decline to name anything. Reading that omission as no restriction let a key its own certificate confines to SHA-1 sign and verify under SHA-256 or SHA-512. Parameters that are present but unreadable are likewise a restriction that cannot be honored, which is not the same as no restriction, so they are refused.
- The RSA credential-key floor is measured in bits. A byte count is not a bit count: a minimally encoded 256-byte modulus whose leading byte is 01 is 2041 bits, seven short of the 2048-bit floor, and cleared a test written in bytes.
- A metadata BLOB signed with RSASSA-PSS, EdDSA or ML-DSA verifies. The reader carried its own six-row JWS algorithm table beside the toolkit's registry, and only the registry had been extended, so PS256 was accepted as an ACME signature and refused as a metadata signature. The table is derived from pki.jose's registry now and is total over it, so an algorithm the toolkit verifies cannot be one this reader rejects: an X.509 SubjectPublicKeyInfo carries an Edwards key (RFC 8410) and an ML-DSA key (RFC 9881) as readily as an EC one. EdDSA names a scheme without fixing a curve, so the certificate decides whether it is Ed25519 or Ed448. An x5c leaf carrying an id-RSASSA-PSS key verifies a PS256/384/512 BLOB, and the restriction that certificate places on the key is enforced in both directions: the key may not verify an RSASSA-PKCS1-v1_5 signature, and where the certificate pins a single hash, a signature under any other is refused.
- The android-safetynet service chain reaches its anchors through the same walk as every other certificate chain in the namespace, and no longer through a second copy of it. An x5c ending in a cross-signed form of the pinned root (the ordinary shape during a CA rotation) now chains, where the local copy left it in the path to fail against a root that never issued it.

## v0.5.2 — 2026-08-12

pki.cms.verify gains a trust seam: name the roots you accept, and the verdict says whether the signer chained to one.

### Added

- pki.cms.verify(input, opts) accepts opts.trustAnchors (the roots the caller accepts, as certificate DER or anchor tuples) and returns trusted alongside valid, with a per-signer trusted on each entry of signers. The signer certificate is chained through the same path engine pki.path.validate uses, with the SignedData's own certificates offered as intermediates and never as anchors. Every signer must chain for the message to be trusted, the same rule the per-signer signature check already followed: reporting the whole as trusted because one signer anchored would let an unanchored signer ride out on another's chain. opts.time picks the instant the chain is judged at. Without anchors there is nothing to chain to and trusted is false: a definite answer, and the same shape pki.cmp.verify returns. Anchors that cannot be read are a caller's configuration mistake and throw; absorbing them into trusted: false would report a verdict about the message for a check that never ran.
- pki.smime.verify forwards opts.trustAnchors and opts.time to the CMS verification beneath it and surfaces trusted in its own verdict. It documents itself as that verdict plus the MIME surface, so the seam had to reach it: building the options from scratch and passing only certs would leave a caller naming anchors with no way to have them applied. It asks for the emailProtection key purpose when anchoring, at both ends of the chain: requiredEku constrains the signer certificate, because a certificate restricted to serverAuth chains to its root perfectly well and is still the wrong key to have signed a message (RFC 8551 sec. 4.4.4), and checkPurpose selects the anchor's own trust metadata, because a root distributed with NSS trust bits can be marked untrusted for email while remaining a good TLS root. Those bits, along with distrustAfter, are consulted only when a purpose is named. Asking one without the other checks one end of the chain and not the other. Pass requiredEku or checkPurpose to ask for something else.
- pki.webauthn accepts RSASSA-PSS credential keys at all three strengths: PS384 (-38) and PS512 (-39) join PS256, in registration and in assertion verification. They were previously refused at parse time on keys that are perfectly well-formed, the same bytes being accepted under -37, so a relying party holding credential rows written by another implementation had some it simply could not check, and could not tell which without scanning its own table. An algorithm this verifier does not implement now reports webauthn/unsupported-algorithm, where it used to report webauthn/bad-cose-key: the key is not malformed, and only one of those two facts tells an operator that re-registering the credential cannot help.
- pki.webauthn.parseCoseKey(bytes) decodes a stored credential public key on its own, and pki.webauthn.verifyAssertion accepts credentialPublicKey as either that parsed object or its COSE bytes. The registration-to-login round trip had a gap in the middle: verify returns the key as an object, but the durable form is bytes. The object carries Buffers, so a JSON round trip through a datastore returns {"type":"Buffer","data":[...]}, and existing credential rows already hold COSE bytes whoever wrote them. The only routes into the decoder parsed a containing structure, so recovering a stored key meant fabricating an authenticatorData that never existed. A registration verdict now also carries credentialPublicKeyBytes, the form to persist.

### Changed

- A signer certificate whose keyUsage forbids signing is not trusted, however well it chains. RFC 5280 sec. 4.2.1.3 makes the extension binding when present, so a leaf asserting keyEncipherment alone must not verify a signature. Path validation checks the CA's keyCertSign, leaving the target's own usage unexamined. The verb that knows a signature was made asks the question, the same format-local gate pki.cmp.verify applies, reading the value through the one strict decoder so a malformed keyUsage fails the gate; a hand-rolled bit test could have authorized it. contentCommitment counts alongside digitalSignature. The signature is still reported sound; what changes is whether the certificate was permitted to have made it.
- pki.cms.verify and pki.tsp.verify refuse an unrecognized option instead of ignoring it. This is what kept the missing trust seam silent: a caller writing trustAnchors before it existed, or trustAnchor now, got a verdict that looked anchored and was not. It matters most between these two verbs, because they spell the anchor option differently: pki.tsp.verify takes trustAnchor, singular, an anchor tuple, while pki.cms.verify and pki.cmp.verify take trustAnchors, plural, accepting certificate DER. Carrying the plural spelling to pki.tsp.verify previously meant no anchoring and no error, leaving an unchained TSA certificate under valid: true. The refusal names the difference.

### Security

- Build and analysis pins move up: github/codeql-action to v4.37.6 across all six references, ossf/scorecard-action to v2.4.4, actions/setup-python to v7.0.0, the ClusterFuzzLite base-builder-javascript image to its current digest, and eslint to 10.8.1. Nothing here reaches the published tarball; the package still declares no runtime dependencies, and every action stays pinned by commit SHA with its version in a trailing comment.

## v0.5.1 — 2026-08-12

Four verify and export paths stop answering a question other than the one they were asked: the key you supply governs, and a private key exports as one.

### Changed

- pki.sigstore.verifyBundle reports identityChecked alongside verified: a boolean per identity field showing which were actually compared. verified: true says the artifact was signed and logged, not that a party you trust signed it. Fulcio issues a certificate to anyone who completes an OIDC flow, so who signed is decided only by opts.identity, and the two claims were previously indistinguishable in the verdict. An opts.identity naming none of san, issuer or sourceRepositoryURI is now refused, since every comparison inside it was falsy: it accepted every signer while reading as a policy in force. An unrecognized field name is refused for the same reason: cosign spells this certificateIdentity, and swallowed it pinned nothing under a name the operator believed constrained the signer.

### Fixed

- pki.webcrypto.subtle.exportKey("raw", privateKey) is refused with webcrypto/not-supported; it no longer answers with the public key. The W3C definition of raw covers public and secret keys; there is no raw private-key serialization for EC or OKP, and Node's own WebCrypto refuses it too. The consequence ran through wrapKey, which forwards the caller's format straight to exportKey: a private key wrapped as raw escrowed the public key, and unwrapping it returned a handle announcing usages ["sign"] that cannot sign, with the private key gone and no error at any step. Use pkcs8 or jwk to serialize a private key; the public half still exports as raw.
- A post-quantum private key exported to a JWK re-imports as a private key. ML-DSA, ML-KEM and SLH-DSA JWKs are kty: "AKP" and carry the private half in priv, while the import tested only for the d an EC or OKP key uses. Every PQC private JWK therefore read as public. The re-imported key was type public yet still announced usages ["sign"], and extractable was forced true even where the caller asked for false: a key that could not sign, said it could, and ignored the extractability it was given. Round-tripping now preserves the half that signs.
- pki.jose.verify treats opts.key as the key the message must be signed under. Where the profile also permits an embedded header jwk, as acme-outer does, the embedded key was preferred and the two were never compared, so the sender chose which key verified its own message and a caller supplying the account key it expected got no benefit from doing so. The two must now be the same key, compared as RFC 7638 thumbprints so member order cannot make equal keys differ, and a disagreement is refused with jose/key-mismatch. The verdict carries keySource, naming which key answered, because a signature checked against a key the caller named is a different claim from one checked against the key the message brought with it.

## v0.5.0 — 2026-08-12

CMC (Certificate Management over CMS) ships end to end: build a Full PKI Request, carry it to a CA over EST, and read the response into one terminal outcome.

### Added

- pki.cmc.verify(response, sent) interprets a Full PKI Response into one terminal outcome: issued, pending, confirm-required, pop-required or rejected. The response is bound to the request that provoked it first. The Transaction Identifier, the Sender/Recipient Nonce echo and the Data Return echo each apply only if the client sent that half, and each becomes a refusal once it did. The nonce is compared in constant time and by full value, so a truncated echo cannot match on a prefix. `bodyPartIDs` binds what the response is about: pass the identifiers the request carried, and a status reporting on a body part that was never sent is refused with cmc/body-part-unknown. The transaction and nonce cannot catch that, because a server can echo both correctly while answering about a different message. Several status controls are permitted and the worst governs, so a failure cannot hide behind an earlier success, and no status control at all is success. Both carriers RFC 5272 accepts work, including the certificate bag an AuthenticatedData keeps under originatorInfo.
- pki.cmc.build(spec, signer, opts) assembles and signs a Full PKI Request across all three request forms: PKCS#10, CRMF, and the other-message arm. Body-part identifiers are allocated unique across the whole message, skipping the reserved 0, and a caller-supplied identifier that clashes is refused and never renumbered, because a control may already reference it. An Identity Proof V2 witness is computed over the reqSequence bytes exactly as emitted, and where an Identification control accompanies it, the key derivation includes that identity as RFC 5272 sec. 6.2.3 specifies. A POP Link Witness is emitted only together with the POP Link Random control sec. 6.3.1.1 requires alongside it, and a renewal carries neither Identification nor Identity Proof, in either version.
- pki.schema.cmc.parse / parsePkiData / parsePkiResponse read the CMC message layer, reached by content type through the CMS carrier. Controls keep their wire order and their raw values, so an unrecognized control is data, and does not read as a fault. Body-part identity is enforced unique across the whole message, covering controls, requests, content infos and other messages alike; uniqueness per list is not enough. The reqSequence bytes are surfaced exactly as they arrived, so an Identity Proof witness is computed over the wire bytes themselves, with no re-encoding in between.
- pki.est.fullcmc(baseUrl, request, opts) POSTs a Full PKI Request and returns the pki.cmc.verify verdict. It accepts either response arm RFC 7030 sec. 4.3.2 names, certs-only or CMC-response, and requires the declared label to agree with the bytes, on the error path as well as the success one. It retains the identifiers its own request carried, so a status reporting on a body part that was never sent is refused; it does not become the answer. A 404 or a 501 is reported as the distinct "not implemented" answer, and no longer as a generic failure, and a rejection surfaces the CMC verdict as a typed est/cmc-failed without letting an unreadable error body mask the HTTP fault it arrived with.
- pki.cms.sign accepts a key-only signer: { key, spki, keyIdentifier } with no certificate. RFC 5272 sec. 3.2 requires exactly this when a Full PKI Request is signed with the key of a certification request it carries. There is no certificate yet, so the signer identifier takes the subjectKeyIdentifier form and carries the identifier the request itself declares, the signature scheme resolves from the request's own public key, and no certificate is embedded.
- pki.webauthn now verifies the authentication half of WebAuthn as well as registration. verifyAssertion(input) checks an assertion signature over authenticatorData || SHA-256(clientDataJSON): raw bytes with no COSE_Sign1 wrapper, and an ES256 signature carried as ASN.1 DER, read with the same order-aware reader the attestation path uses, so an r or s outside [1, n-1] is refused, with no normalization. Give it the previousSignCount you stored and the sec. 7.2 step 21 counter rule applies: a counter that fails to advance is refused as the cloned authenticator it signals, while the 0/0 case an authenticator without a counter reports is accepted. parseAuthenticatorData(bytes) reads the bare authenticatorData an assertion carries, through the same fail-closed parser registration uses. parseClientData(bytes, opts) decodes the clientDataJSON that no signature check ever looks inside, through the shared JSON guard since these are bytes an attacker chose, and returns the challenge decoded, so the caller's comparison is a byte comparison.
- pki.webauthn.verify accepts opts.rootCertificates, the attestation trust anchors a caller pins. Anchoring previously ran only through a FIDO Metadata Service entry, which reaches only the models that catalogue lists: Apple does not publish its authenticators to it, and the Google hardware-attestation roots are distributed by Google, so for those formats there was no parameter to carry a root and a trust path came back unchecked. The precedence is stated explicitly. opts.metadata governs when supplied, because a model's own registered roots are a stronger claim than a static pin and its status reports can disqualify a model those roots would still accept; opts.rootCertificates is the route for everything the catalogue does not cover. Supplying both is the ordinary configuration for a relying party that accepts MDS-listed authenticators as well as Apple. Every verdict now reports anchoredTo, naming every route that anchored the path and joining them with + when more than one did: "metadata", "rootCertificates", and "safetyNetRoots" for the android-safetynet chain, which anchors through the roots that format requires whether or not either other route was asked for. It is null only when nothing anchored the path. A compound holding one element the catalogue lists beside one it does not is anchored element by element, each against the roots its own route supplies, where before it would have been refused, and the verdict keeps the entries that governed so the metadata-backed half of the decision stays auditable.

### Changed

- 79 APIs graduate from experimental to stable, taking the stable surface from 78 to 157: the whole of pki.cms, pki.tsp, pki.ocsp, pki.smime, pki.cbor, pki.merkle, pki.crmf, pki.inspect, pki.trust, pki.tls and pki.shbs; the offline CMP message layer (build and verify); pki.path.validate / crlChecker / ocspChecker / verifyOcspResponse; the pki.webauthn attestation surface and its FIDO metadata reader, the assertion verbs being new here and shipping experimental; and the pki.schema decoders for S/MIME attributes, TSP requests and the engine itself. Each rests on a final standard and is proven either against an independent implementation in the interop harness or, for the formats no mainstream tool implements, by conformance-vector round-trip plus coverage-guided fuzzing. Stable means the deprecation policy now applies: no silent breaking changes, and a deprecation warning at least one minor before any removal.
- 68 APIs stay experimental, each with a written reason and a re-review date attached. Four things hold one back. The standard is not final: pki.schema.c509 tracks an IETF draft, the Sigstore bundle format is still moving, and all of pki.ct rests on RFC 6962, which is published Category: Experimental however widely CT v1 is deployed. The surface is knowingly incomplete, so its own output will change: pki.hpke has no post-quantum KEMs yet, and pki.lint's rule set is still growing. It first ships in this release with no soak behind it: pki.cmc, pki.schema.cmc, pki.est.fullcmc, and the pki.webauthn assertion verbs. Or it is a network client waiting on the shared pki.transport (pki.est, pki.acme, the driven half of pki.cmp, and the opt-in AIA fetching in pki.path.build), which is still absorbing a fail-closed requirement from each new protocol that composes it, and this release added another.
- An AuthenticatedData response is authenticated by its MAC. Pass pki.cmc.verify a recipient with the key material, the shape pki.cms.decrypt takes, and the MAC is checked, so a caller holding the key gets an authenticated verdict instead of the unauthenticated opt-out. The content the MAC covers is bound to the content the verdict was read from, so a MAC over other bytes cannot stand in for it, and a wrong key is reported in this layer's own terms, with no CMS code leaking through.
- A Full PKI Response must be authenticated before it is interpreted (RFC 5272 sec. 3.2.1.3.4). A conforming response carries its own signer certificate, so the ordinary flow needs nothing extra and the verdict reports signatureVerified: true. Where the signer is found nowhere, neither in the message nor supplied, the opt-out has to be named: pass certs with the responder's certificate, or allowUnverified: true, in which case the verdict reports signatureVerified: false. Doing neither is refused, so no caller ends up assuming a check that did not happen, and the opt-out never excuses a signature that is present and wrong. A carrier with no signer at all is refused outright. pki.est.fullcmc threads this through as responderCerts and allowUnverifiedResponse, on both the success and the rejection paths.
- A pki.webauthn verdict can no longer be mistaken for a ceremony verdict. The field is attestationVerified, and signatureVerified for an assertion, where it used to be verified. An attestation statement being sound is a different claim from a registration being acceptable: a statement naming another relying party, with user presence clear, is perfectly sound and must not be registered. The bindings this layer can check are now offered by name: expectedRpId, requireUserPresence, requireUserVerification, allowedAlgorithms, and for clientDataJSON the ceremony type, challenge and origin. Every verdict reports which of them actually ran in bindingChecked, so a check that passed is distinguishable from one that never happened. The ceremony type is checked unconditionally when verifyAssertion is given the JSON, since the specification fixes which ceremony a response belongs to and the caller does not choose it, and a registration response replayed as a login is what that check stops. A registration verdict also now carries the credentialId, credentialPublicKey and initial signCount a later login needs, which previously required parsing the attestation object a second time.

### Fixed

- A CMC status control carrying the OPTIONAL statusString (the human-readable explanation a CA sends with a rejection, so it is on the common path) crashed the decoder with a raw TypeError instead of returning the string, because the reader it named does not exist. pki.schema.cmc.parse, pki.cmc.verify and pki.est.fullcmc were all affected. Every CMC decode now goes through a reader the codec actually exports, and a gate checks that across the whole tree by reading the codec's own export list, so a mistyped reader cannot ship again.
- pki.cmc.build takes transactionId, senderNonce and dataReturn as named spec fields, the same three pki.cmc.verify checks a response against. They previously had to be hand-encoded into spec.controls, and an unrecognized spec field was accepted in silence, so a request written the obvious way built, signed and sent with no exchange binding at all. Neither end could detect that, because the verifier only enforces the halves the client says it sent. An unknown spec field is now refused.
- pki.cms.verify and pki.cmc.verify parse a private copy of a Buffer input, so the value they report and the bytes the signature was checked against are provably the same. Both decode the message synchronously and check signatures in a later turn, which left every byte range the parse surfaced, the signed content above all, a view into the caller's memory across that gap. A buffer rewritten in between could yield a result describing one message while the signature covered another, and the everyday way to hit it is a pooled read buffer recycled across concurrent verifies. A PEM string or an already-parsed object is untouched, so neither call accepts less than it did.
- Every example in the API documentation runs against the shipped package as part of the test suite, with no fixtures supplied to it, and the ones that did not run have been corrected. An example that quietly depended on a value the surrounding text never defined would previously have failed only for the operator who pasted it.
- pki.webauthn.verify copies opts.rootCertificates synchronously, so pinned attestation roots cannot be swapped out from under the check. The roots are not read until the attestation verifier resolves, a later promise turn, and both the array and each DER buffer stayed caller-owned across it: a caller recycling the array or overwriting a certificate's bytes in that gap had the attestation anchored against the replacement roots while the verdict still reported anchoredTo: "rootCertificates". Both are now copied at the entry point, the same defense the assertion input already had, and the documented parsed-certificate form is deep-copied and never passed by reference, since the anchor comparison reads its nested subject and subjectPublicKeyInfo buffers. opts.safetyNetRoots carried the identical window one level down, since a format verifier reads it a microtask after the call returns, and is snapshotted at the same boundary.
- In a compound attestation, an element the metadata catalogue does not list can no longer launder a revoked sibling. The two governance failures are not equal: metadata-not-found is the one outcome a caller may fall back to opts.rootCertificates on, and that fallback covers the whole statement. Governance stopped at the first failing element, and a compound's element order is not signed, so placing an unlisted element first raised the fallback error before a listed-but-revoked sibling was ever consulted, and the statement anchored against the pinned roots instead. Every element is now governed, and every listed element chain-validated against the roots its own entry registers, before any outcome is chosen. So a disqualifying status report outranks an unlisted sibling from either position, and a listed element whose path reaches the caller's pinned roots but not its own registered roots can no longer ride out on that sibling's fallback either. A compound in which no element is listed still falls back as documented.
- pki.ocsp.sign copies the responder key synchronously. The key is not read until several promise turns after the call, and capturing only the reference stopped responder.key being reassigned but not the PKCS#8 bytes, or a composite key's components, being rewritten in place. Either produced a response carrying this responder's identifier and embedded certificate over a signature made by different key material, which no relying party can verify. A CryptoKey is opaque and a PEM string immutable, so both were already safe. A composite descriptor is cloned whether or not its components currently hold bytes: one carrying two PEM strings has nothing mutable inside it, but the object is still the caller's, and reassigning a component reaches the deferred sign just as rewriting a buffer would.
- An Apple attestation certificate whose anonymous-attestation extension carries more than the nonce is refused. AppleAnonymousAttestation is a SEQUENCE of exactly one field wrapping exactly one value, but the decoder read the first child and ignored the rest, so a certificate with a trailing field beside the nonce, a second value inside the EXPLICIT [1] wrapper, or a non-SEQUENCE outer value was accepted. That extension exists to carry the value the attestation binds to, so an ambiguous encoding of it is not a shape the verifier gets to pick a reading from; arity is now enforced as part of the declared type.
- A key identifier and a pre-encoded CertID must now be bytes, and are no longer coerced. pki.cms.sign takes a key-only signer's keyIdentifier and pki.ocsp.sign takes a response entry's certID straight into the encoding, and both previously ran the value through Buffer.from, which accepts far more than it should mean: Buffer.from(20) allocates twenty zero octets and Buffer.from("a1b2") takes the ASCII of the text where a reader means two octets. Either produced a structurally valid but wrong SignerIdentifier or CertID, inside a message that then gets signed and that no verifier can match back. A Buffer or Uint8Array is accepted as before; anything else is now cms/bad-input or ocsp/bad-input.
- An OCSP response whose nonce does not echo the request no longer downgrades a revoked verdict to unknown. pki.ocsp.verify applies that downgrade to good only. Revocation does not go stale the way non-revocation does, so discarding a signed, current, authorized revoked response because it was replayed would hand a soft-failing caller the certificate the responder just refused: the anti-replay defense would become the thing that accepts it. The verdict was also self-contradictory, reporting status unknown while carrying revocationReason keyCompromise. nonceMatched: false still reports that the response was not bound to this request, and the field is now three-state and always present (true bound, false not bound, null when the client sent no nonce), so a caller can tell a check that ran from one that was never asked for.
- Corrections to the repository documentation, each of which would have misled a reader who acted on it. SUPPORT.md described additive APIs as minor releases; pre-1.0 they ship as patches, and a minor is an explicit decision recorded in the release notes. ARCHITECTURE.md, CONTRIBUTING.md and the interop test guide showed pki.x509.parse, which does not exist: parsing is pki.schema.x509.parse, and pki.<format> is the issuing half throughout. ARCHITECTURE.md listed namespaces as future that have shipped, and omitted the schema, guard and validator families entirely. THREAT-MODEL.md marked path validation, signature verification, CMS decryption and ML-KEM decapsulation as targeted when all four have shipped, and linked to a section that no longer exists. ROADMAP.md reported CRL reason-shard accumulation and delta-CRL merge as planned in one entry while describing them as shipped in another. ML-KEM encapsulation and decapsulation were described as roadmap items; both ship and are what the CMS KEMRecipientInfo arm rides on. The interoperability acceptance gate was described as running against NSS, Windows CAPI and macOS Keychain alongside OpenSSL; only the OpenSSL cross-checks are wired, and the others are roadmap. The format detectors behind pki.schema.parse were described as mutually exclusive regardless of registration order; order is load-bearing where two overlap, so a CMP PKIMessage sits ahead of the OCSP-request probe and a v1 attribute certificate ahead of X.509. The fuzzing guide listed 27 of the 55 harnesses. The README carried two separate entries for pki.tls. The published pki.transport response contract named three fields where the transport returns four: the omitted tls field is what pki.est.serverkeygen reads to assert the channel can protect a server-generated private key, and a transport that reports no cipher is trusted, so an operator injecting a substitute built to the documented contract silently skipped that check. EST channel binding was described as shipped; the challengePassword builder and the server-instruction flag ship, but nothing produces the RFC 5929 tls-unique value and the shared transport does not expose it, so the attribute cannot be driven end to end.

## v0.4.15 — 2026-08-10

A CA that partitions revocations by reason code, or publishes a delta CRL alongside its base, now gets a real answer instead of "undetermined".

### Added

- Reason coverage accumulates. Each CRL that corresponds to one of the certificate's distribution points contributes its interim reason mask (RFC 5280 sec. 6.3.3(d)(1)-(4)), and the certificate reads good once the CRLs together cover all eight revocation reasons (sec. 6.3.3(l)). Previously only a CRL that covered every reason by itself could establish good, so a reason-partitioned CA could never be satisfied. Partial coverage still fails closed, and a shard that does not correspond to the certificate contributes nothing while still being consulted for revocation.
- Delta CRLs are merged onto a complete CRL they may be combined with (sec. 5.2.4(a)-(d), sec. 6.3.3(c)): same issuer, byte-identical issuing distribution point and authority key identifier, and a base number the complete CRL's own number covers. The delta is searched first, the complete CRL only if the delta left the certificate unrevoked, and a removeFromCRL entry then releases it, so a certificate placed on hold and later released now reaches good, where it used to stay rejected. A delta is merged only when the certificate or the complete CRL carries a freshestCRL locator (sec. 6.3.3(a)(2)).
- pki.path.crlChecker(crls, opts) takes opts.useDeltas (sec. 6.3.1(b)), default true. With it false a delta is never merged; it is still consulted for revocation.
- A revoked verdict carries reasonCode, the CRLReason integer (0 for unspecified when the entry has no reasonCode extension), and a reason naming it, so an operator learns that a certificate was revoked for keyCompromise, where before the verdict said only that it was revoked.

### Changed

- Merging can only ever turn an undetermined verdict into good or revoked. A delta that combines with no complete CRL held locally is still consulted for the revocations it lists, and still withholds good, so an unmergeable delta can never erase a revocation, including one that names a base the verifier does not have. Where several current deltas exist for one scope, which RFC 5280 sec. 5.2.4 permits, the one with the latest thisUpdate is selected, and the set is not treated as a fault.
- The reasons field of a certificate's cRLDistributionPoints is now rejected unless minimally encoded, matching the rule already applied to keyUsage (X.690 sec. 11.2.2 named bit lists). Two encodings of one reason set previously both parsed, which would leave the reason intersection computed over an encoding the rules forbid.
- A delta CRL indicator that is not marked critical, which RFC 5280 sec. 5.2.4 requires it to be, does not make the CRL mergeable. Such a CRL is still treated as a delta and still consulted for the revocations it lists, as before, but it cannot release a certificate its base revoked. Releasing rests on a conforming indicator.
- An issuing distribution point that is not marked critical cannot contribute reason coverage at all. Such an extension is one a relying party may ignore entirely, so building a good verdict on the scope it declares would rest on something another verifier would not see; that is the same fail-closed reasoning already applied to distribution-point correspondence. It still restricts nothing and withholds good, exactly as before this release.
- A CRL number past the RFC 5280 sec. 5.2.3 twenty-octet ceiling does not make a CRL mergeable, matching the bound pki.crl.sign already enforces when emitting one. Such a CRL is still consulted for the revocations it lists; only the ability to release a certificate is withheld.

### Fixed

- Holding a delta CRL alongside its base is no longer worse than holding the base alone. Any authoritative delta previously forced the whole verdict to undetermined.
- A CRL that covers no revocation reasons for the certificate, such as a shard whose distribution point does not correspond to it, is now checked for currency and signature before it is consulted at all. Such a CRL is still read for revocations, so without those checks an expired or forged one could have revoked a certificate it never legitimately covered, or, as a delta, released a certificate its base genuinely revoked.
- A delta CRL superseded by a more recent one for the same scope no longer affects the verdict in either direction. It could previously contribute a revocation that the selected, later delta had released; that resurrected a revocation the CA withdrew, while its own release was correctly ignored.

## v0.4.14 — 2026-08-10

Every key-establishment secret this library allocates is now wiped when it stops being needed, classical as well as post-quantum.

### Changed

- Raw secret key material is now reached through a single path that clears the copy it hands out, so a new operation cannot obtain that material without the wipe. Behavior of the public API is unchanged.

### Fixed

- The raw shared secret of an ECDH / X25519 / X448 key agreement is cleared once the derived bits have been produced, including on the exit where the caller asks for the whole secret and on the error when more bits are requested than the curve provides. It was previously left readable for the process lifetime after every key-agreement operation.
- The AES content-encryption key is cleared after every encrypt and decrypt. The key material was exported into a fresh buffer on each call, with no clear afterwards, so an application that encrypted or decrypted repeatedly accumulated a readable copy of each content key. This covers GCM, CBC and CTR in both directions.
- A key-derivation function now clears the copy it makes of its input keying material. This was already done for HKDF; the X9.63 and PBKDF2 derivations on the same dispatch did not, and the X9.63 one holds the ECDH shared secret of an RFC 5753 key-agreement recipient.
- The content-encryption key of an enveloped message is cleared once the message is built, and the recovered one is cleared once the content is open. Because that key is wrapped for every recipient, the clear happens once at the end and never per recipient, so a message with several recipients still opens correctly for each of them.
- The password-derived key-encryption key of a password recipient, and the password-derived content key of a password-protected EncryptedData, are cleared on both the producing and consuming sides. That includes a wrong password, which is the path an attacker repeats.
- When a PKCS#1 v1.5 key-transport unwrap hits a decode fault, the decryptor continues with a fresh random substitute content key so the failure stays indistinguishable from any other bad-key path (RFC 3218). That substitute is now cleared too, since it is allocated only on the failing path, which is the one an attacker drives repeatedly.
- The message-authentication key of an AuthenticatedData is cleared on both sides: the producer generates it, wraps it for every recipient and clears it once; the consumer clears it after the MAC and message-digest checks, including when a tampered message fails them.
- Password-based private-key protection clears the key it derives. pki.key.encrypt / pki.key.decrypt and the shared PBES2 encrypt / decrypt used by PKCS#12 each left the password-derived key readable after use. That key guards a private key, which is the most sensitive thing this library encrypts.
- PKCS#12 integrity clears the password-derived MAC key on both sides (when a store is built, and when its MAC is recomputed to verify it), and the legacy-PBE decryption arm clears its derived key, which its PBES2 sibling on the same dispatch already did. The PBMAC1 key, shared by both, is cleared as well.
- HPKE clears the raw Diffie-Hellman output on every DHKEM arm: base and authenticated, sealing and opening, including the concatenated form the authenticated modes build from two agreements.
- A key-derivation function returns an exact-sized buffer the caller wholly owns, and no longer a window onto a larger accumulator. Where the requested key size is not a multiple of the digest length, as for an RC2 key from a SHA-1 block or an X9.63 or HPKE derivation of an odd length, clearing the returned key previously left the unused tail of the final derived block readable behind it.
- Key-derivation intermediates are cleared as they are superseded: the HPKE extract and key-schedule pseudorandom keys, and each digest round and input block of the PKCS#12 derivation, whose accumulator is now allocated once at its final size; regrowing it each round abandoned an unreachable password-derived copy per iteration.
- An HPKE recipient clears the shared secret it derives once the key schedule has consumed it, and the single-shot seal / open clear the encryption context they build and discard: its AEAD key, base nonce and exporter secret. A context obtained from setupS / setupR belongs to the caller and is untouched, so a multi-message exchange is unaffected.
- A derivation or decryption result is cleared once it has been copied out to the caller. The PBKDF2 and X9.63 outputs, and the RSA-OAEP decryption output, which for a key-transport recipient is the recovered content key, were each copied into the returned buffer and then abandoned, leaving key material readable that no caller could reach to clear.
- A password supplied as a string or Uint8Array is encoded into a buffer this library allocates, and that credential encoding is now cleared once the derivation has consumed it. Previously only a caller-supplied Buffer was handled, and it was handled by leaving it alone, so the common case left the encoded password readable. A caller-supplied Buffer is still borrowed and never written to.
- The RFC 3211 password key-wrap clears its plaintext intermediates. Both the formatting block built around the content key when wrapping, and the recovered block when unwrapping, held a complete copy of that key and were abandoned; on the unwrap side that includes the two validation rejects, which are the paths an attacker induces by tampering with the wrapped key.
- Wrapping a key clears the plaintext serialization it makes of that key (the very material the wrap protects) on the delegated RSA-OAEP / AES-GCM branch as well as AES-KW. HPKE clears the labeled input copy its extract step builds around a shared secret or PSK, and clears the sender secret when setup itself rejects.
- A password is encoded only after its options validate, so a rejected iteration count or salt cannot abandon a credential copy; the PKCS#12 derivation clears the block-repeated salt and password fills it builds; and the HPKE expand clears each round feedback input, which carries the previous output block.
- Every site that builds a PKCS#12 password encoding clears it: store integrity on both sides, and legacy-PBE decryption. The clear happens only when this library allocated the encoding. A password supplied as a Buffer is passed through that encoder unchanged, so it stays borrowed and is never written to, exactly as on the CMS paths.
- Deriving a key clears the transient bits it derives once they have been imported into the key object, including when the import itself rejects.

## v0.4.13 — 2026-08-09

A KEM shared secret and the key it derives are now wiped as soon as they stop being needed. The failing path clears them too, and that is the path an attacker chooses.

### Added

- A KEM shared secret and the key-encryption key derived from it are wiped as soon as they stop being needed, satisfying NIST SP 800-227 RS5 / sec. 4.2 and RFC 9629 sec. 7. The wipe runs in a finally, so a decryption that fails clears the same buffers a successful one does. A wipe on the success path alone would preserve the secret in exactly the case an attacker can force. Only buffers this library allocated are cleared; a caller's key material, certificate, and the returned plaintext are never written to, and the plaintext remains usable after the wipe.
- This is best-effort, and is documented as such. The runtime copies a shared secret into places no code can reach (the decapsulation result on its way out, and again when it is imported as key material) and may relocate a buffer's backing store. Wiping the copies the library holds shortens the window in which a secret is readable; it does not mean a secret never persists in memory.
- pki.oid.kemParams resolves an ML-KEM parameter set to its FIPS 203 Table 3 sizes, by dotted OID or by registered name.

### Changed

- The ML-KEM ciphertext-length check FIPS 203 sec. 7.3 requires of a decapsulating party is now performed by the crypto engine, so a caller reaching decapsulateBits directly is covered too; before, only the CMS path that happens to call it today was. It reports webcrypto/bad-kem-ciphertext, naming the parameter set and both lengths, where the failure was previously indistinguishable from any other decapsulation fault; a ciphertext whose length is valid for some other parameter set is refused on those terms, and no longer reads as merely short. The check is on length alone: a correct-length ciphertext that has been tampered with still resolves to a pseudo-random shared secret, because turning that into an error would give an attacker a decryption oracle. No engine detail reaches a CMS caller: a structurally valid message whose decryption fails for any secret-dependent reason still reports the single uniform cms/decrypt-failed verdict. A message whose ML-KEM ciphertext length does not match the parameter set the message itself declares is a separate case and always was (including a length that would be valid for a different set), because the strict parser rejects it up front and names it: the mismatch is a structural fault, decidable from the message alone, with nothing about it depending on a key.
- The ML-KEM parameter sizes resolve from one registry instead of three separate tables in three modules. The encapsulation-key lengths were already duplicated verbatim in two of them, and each new consumer meant another copy that could drift; a parameter set is a property of the algorithm identifier, so it now lives beside the registry that resolves one. Behavior is unchanged.

### Fixed

- The roadmap attributed two rules to NIST SP 800-227 that it does not state: implicit rejection and re-encapsulation are FIPS 203's, reached through SP 800-227's requirement to comply with the KEM's own standard, and SP 800-227 sec. 4.3 explicitly permits a shared secret to be used directly, truncated, or split into segments. The unconditional key-derivation requirement comes from RFC 9629 sec. 5. The entry now states what each document requires.

## v0.4.12 — 2026-08-09

A CMS message can no longer declare one content cipher and be opened with another: the declared algorithm's mode is now bound to the container that carries it, so an EnvelopedData naming an authenticated cipher is refused. It used to be opened, unauthenticated, under a result that reported it as authenticated.

### Added

- pki.lint reports the RFC 5280 sec. 4.2.1.4 rules for a certificate policy's user notice, at the strength the specification states each one: encoding a notice as VisibleString or BMPString is an error, since conforming CAs must not; a notice past 200 characters, an empty one, and one containing control characters are warnings; a UTF8String notice that is not in Unicode normalization form C is a notice. The length is measured in characters, so a conforming notice whose accented or emoji characters occupy more storage than 200 units is not reported, and a value whose contents do not decode under its own declared string type is not measured at all. The encoding rule, which the ASN.1 tag alone answers, still reports it. The rules live in the linter and not the decoder deliberately: the same section directs certificate users to handle an over-long notice gracefully, so a verifier that refused one would reject certificates that exist and are otherwise valid.
- The two ends of the SIZE (1..200) bound report separately, because the section treats them differently: it directs certificate users to handle a notice above 200 characters gracefully and says nothing of the sort about an empty one, so suppressing the first must not silently suppress the second. Both cover a notice reference's organization as well as the explicit text, since the bound belongs to the DisplayText type itself, which both fields use.

### Changed

- pki.inspect renders a certificate policy's user notice as text. A user notice is a constructed value, so it previously fell to the hexadecimal fallback and an operator could not read the notice the qualifier exists to display; its explicit text and its notice reference now render, the reference carrying its organization together with the notice numbers that identify which notice is meant.
- pki.inspect renders an authority-information-access location given as a directory name. It previously printed a bare form tag, hiding the responder or issuer identity the entry exists to convey, while the same name form already printed as a distinguished name elsewhere in the report.
- The producing entry points state their error contract completely. pki.x509.sign, pki.csr.sign, pki.crl.sign and pki.attrcert.sign accept raw DER for a name, a pre-encoded extension, or a public key; a structural fault in those bytes raises the format's own error, while a malformed leaf inside them raises the codec's, which the parsing entry points already documented and these did not.

### Fixed

- A CMS content cipher is now bound to the container that declares it. An EnvelopedData must name a CBC cipher and an AuthEnvelopedData an AEAD one, checked before the content-encryption key is used; a mismatch is refused as an unsupported algorithm naming both the cipher and the container. Previously only the cipher's key length was resolved, and because AES-CBC and AES-GCM share key lengths, an EnvelopedData whose algorithm identifier had been changed to the same-size AES-GCM identifier decrypted successfully as unauthenticated CBC while reporting the AEAD algorithm in its result. A caller inspecting contentEncryptionAlgorithm to establish that the content was authenticated was answered from a field the decryption had not honored. The reverse pairing was refused only incidentally, by a later dereference of parameters the AEAD path expects, and no stated rule refused it.
- The password-recipient inner cipher is resolved through the same identifier-keyed table. It previously required a CBC mode by matching the algorithm identifier's display name, which pki.oid.register can rebind, so a caller that had registered a name over a built-in one could change which ciphers that check admitted.

## v0.4.11 — 2026-08-09

A WebAuthn attestation can now be bound to the roots the authenticator's own model actually registered, by reading a FIDO Metadata Service BLOB that is verified and chained to a root you supply before any of its contents are parsed.

### Added

- pki.webauthn.verifyMetadataBlob reads a FIDO Metadata Service (MDS v3) BLOB and returns its entries indexed by aaguid. The BLOB is a JWS: its signature is checked under the certificate in its own header, that chain is validated to one of the roots the caller pins, and only then is the payload parsed. The ordering is the point, because a reader that parses first hands an attacker every structure behind the signature.
- The catalogue's freshness is enforced, and enforced again wherever it is used. A BLOB whose sequence number does not exceed the one the caller already holds is refused as a rollback, and requireRollbackCheck makes supplying that number mandatory so the check cannot be skipped by forgetting the option. A BLOB past its nextUpdate is refused as stale. A verified result is an ordinary object a relying party may cache, so its expiry is re-checked each time it is passed to verify, and a catalogue fetched while current cannot keep authorizing an authenticator whose status reports have since revoked it. Both checks fail closed, and the caller's own allowStale decision rides on the result, so it need not be repeated.
- Passing the verified result to pki.webauthn.verify as opts.metadata binds the attestation to its own model: the authenticator's registered attestation roots are resolved from its identifier, and its trust path must fully validate to one of them. That means signature chaining, validity and constraints: the same path validation any certificate chain gets. An authenticator whose model the catalogue does not list, whose entry registers no attestation root, or whose status reports disqualify it, is refused. Which reports disqualify is selectable: any report ever filed, only the most recent one so that a later remediation clears an earlier revocation, or a predicate of the caller's own. An unrecognized status is ignored by default, as the specification requires, or treated as disqualifying on request.
- Authenticators that carry no aaguid are covered too. A U2F authenticator declares no model identity, and the catalogue keys it by the key identifiers of its attestation certificates instead; both key spaces are indexed and looked up, so a U2F registration binds to its registered roots and is not refused as unlisted. The identifier is read from the entry and from its metadata statement, since live entries populate both, and is computed as RFC 5280 sec. 4.2.1.2 method 1 defines it. A compound attestation is covered as well: its elements carry independent trust paths, and every one of them must reach a registered root.
- Which identifier is allowed to select an entry depends on what the attestation signature covers. The fido-u2f signature is computed over named fields and does not include the aaguid, so for that format the certificate decides and the declared aaguid is ignored; otherwise setting it to a listed model that shares the vendor's registered root would resolve to that model's entry and skip the real one's status reports. For relying parties: res.aaguid reports what the authenticator presented and is not signature-bound for that format; res.metadata.aaguid names the entry that actually matched.
- Only a catalogue this library verified can decide anything. A metadata result is recognized by its provenance. Shape is not enough on its own, so an object restored from a cache is refused as a catalogue. It has been through none of the signature and chain checks, and its contents are whatever an attacker able to write that cache chose. Re-verify the BLOB instead, which the freshness rule asks for anyway. The verified result is also frozen. The catalogue that decides a later verification is therefore the one the signature covered, unedited.
- A stored attestation is anchored at the instant its own format judged it. An android-safetynet response carries its signing time and its service chain has usually expired since, so the metadata anchor check reuses that instant in place of the current clock; otherwise it would refuse the very registration the format verifier had just accepted. An explicit opts.time still takes precedence.
- Status reports are read against the instant being judged: a report dated in the future has not taken effect, so it cannot displace a revocation that is in force now, and a deliberately historical verification does not see reports filed after the time it asks about.
- A status report that names a single certificate is judged against the certificate actually presented. A whole batch of authenticators is commonly listed under one entry, so a key-compromise report naming one attestation certificate denies only that one, whatever else the entry covers; a report that names nothing, or names something that does not decode, still applies to the entry as a whole. Trust anchors are recognized by name and public key. Self-issuedness is not the test, so a chain terminating in a cross-signed form of a root you supplied still anchors to it.
- The BLOB's own signing certificate must be permitted to sign. A certificate that carries a key-usage extension omitting digitalSignature is refused before its key is used to check the BLOB signature, so a certificate restricted to some other purpose cannot confer metadata-signing authority just because it chains to the root you supplied.
- pki.webauthn.metadataFor looks an entry up against a verified result only, never raw bytes, so a lookup cannot be answered out of a catalogue nobody verified. It takes either identifier (an aaguid or an attestation-certificate key identifier), dispatching on the form, which are disjoint by shape. pki.webauthn.metadataAnchors decodes an entry's registered attestation roots one entry at a time, since a handful of certificates in the live metadata do not parse under a strict decoder and decoding everything up front would let one vendor's malformed root refuse the entire catalogue for every other authenticator in it.

### Changed

- pki.webauthn.verify now rejects an unrecognized option key, where it used to ignore one, and validates opts.time at the boundary. Every option it takes either gates the verdict or supplies the trust material a gate needs, so a misspelled key was not harmless: asking for metadata enforcement and mistyping the key left the gate switched off and returned a pass the caller believed had been checked against the catalogue. An invalid time is now reported as the configuration fault it is, and no longer surfaces later as an authenticator trust failure.
- Configuration objects across certificate, CRL, attribute-certificate, CSR, and CMP issuance now reject an unrecognized option key through one shared check, replacing a dozen separate ones. Two cases that a hand-written check gets wrong are fixed everywhere at once: a key that every JavaScript object inherits, such as constructor or toString, is no longer accepted as a recognized option name, and an option object built by parsing JSON that carries its own __proto__ key is now inspected; it used to be skipped. The wording of every rejection is unchanged. This matters because the failure is silent in the quietest possible way: a misspelled option key leaves the default in force, so a caller who asked for a stricter check gets the looser behavior and no error anywhere.

### Fixed

- An invalid opts.time passed to pki.webauthn.verify for an android-safetynet attestation raised an untyped internal error instead of the typed webauthn/bad-input verdict. Every failure from the verifier is a typed error again, so a caller catching pki.errors.PkiError no longer has a hole on that path.

## v0.4.10 — 2026-08-08

A TPM attestation now reports the credential key's own object attributes and access policy, so a relying party can require the properties it cares about (a key bound to one TPM, generated by that TPM, not duplicable) instead of taking the attestation on trust.

### Added

- A verified TPM attestation reports the credential key's object attributes as named flags, the raw attribute word, and the key's access-policy digest. Previously both fields were read past and discarded, so a relying party that wanted to know whether the key was bound to its TPM had to re-parse the public area itself.
- opts.tpmPolicy requires any of those attributes by name, in either direction, since an attribute may be required set or required clear; it refuses the attestation naming which one disagreed. A single profile, hardware-bound, is the shorthand for the six attributes every genuine attestation examined agrees on: the key is bound to one TPM and one parent, the TPM generated it, it can sign, and it is neither a restricted key nor an X.509 signing key. An explicit attribute layers over the profile, so one flag can be overridden without losing the rest. Three attributes are deliberately absent from it, because they differ across genuine authenticators and requiring any of them would reject working hardware.
- The policy also covers the key's access policy: requiring that one is present at all and is not the empty policy, and requiring it to be one of an allow-list of digests, compared in constant time. Two structural opt-ins are available for callers who want them: rejecting an attribute word that sets a bit the specification reserves, and rejecting attribute combinations the specification does not define.
- A mistyped policy is refused when it is set: an unknown key at any level, an unknown profile, an unknown attribute name, a non-boolean value, or an allow-list entry that is not a certificate digest all fail immediately, so a typo can never silently disable the check a caller believes they enabled. Names that every JavaScript object inherits are not accepted as policy names either, since a lookup would otherwise report them as recognized and leave the policy applying nothing. Requiring that the TPM generated the key without also requiring the key be non-duplicable is refused for the same reason. On its own it establishes nothing, because the key could have been imported.
- Requesting a TPM policy also requires an attestation that can satisfy it. The policy is evaluated against the TPM public area, which only a TPM attestation carries, so an attestation in any other format would never reach it, and a relying party that demanded a TPM-bound key would have accepted a credential with no attestation at all. Such a request is now refused up front, naming the format, and a compound attestation qualifies only when it actually contains a TPM statement.

### Fixed

- Calendar dates without a time are now read through the same strict reader as full timestamps. A date that does not exist is rejected: the thirtieth of February is refused, where the language would have rolled it into the following month and silently made it the second of March. A parsed date is anchored to UTC, so a freshness or expiry comparison does not shift with the host's time zone.

## v0.4.9 — 2026-08-08

A WebAuthn compound attestation now verifies, and every nested statement must pass, so a wrapper cannot launder a failed attestation behind one that succeeds. The certificate chains an attestation carries are also bounded by count, not only by size.

### Added

- pki.webauthn.verify verifies the compound attestation format, which it previously refused as unsupported. Every nested statement must verify for the attestation to verify. The specification leaves the threshold to relying-party policy, and this is the fail-closed reading of it. The result reports attestation type Compound and carries each element's own verdict, attestation type and certificate chain in order, so a caller applies its own policy to the parts. A merged verdict could overstate or understate any of them. The combined trust path is empty by construction: several elements produce several independent chains, and presenting them as one ordered path would misrepresent what was validated.
- The nested statements are held to the format's own syntax: at least two of them, each exactly a format identifier and a statement, each identifier matched case-sensitively against the supported set, and none of them compound; the specification spells that exclusion out, so nesting is impossible by construction and needs no depth counter. Each format now declares which CBOR shape its statement takes, where the shape used to be fixed for all of them, so accommodating the array-shaped compound statement leaves every other format's contract unchanged, and a compound presented in the older map shape is refused.

### Fixed

- The number of certificates an attestation may carry is now bounded. Both the attestation statement's certificate array and a JSON Web Signature certificate header capped the size of each certificate but not how many there were, so a statement could present thousands of small certificates and each one cost a parse and, downstream, a full path validation, work far out of proportion to the bytes on the wire. A single bound now covers every place a chain arrives, set well above any real attestation chain.

## v0.4.8 — 2026-08-08

A stored android-safetynet WebAuthn attestation can be re-verified in full (the signature, the registration binding, and the certificate chain) behind an opt-in and against a root the caller supplies.

### Added

- pki.webauthn.verify verifies the android-safetynet attestation format, which it previously refused as unsupported. Enable it with opts.verifySafetyNetJws and supply the Google root(s) to anchor the chain to as opts.safetyNetRoots. Both are required; with either missing the call is refused and never falls back to a weaker check. The format is off by default and this library bundles no root, because the service that produced these statements is retired and choosing a trust anchor on a caller's behalf is not this library's decision to make. A caller who does not enable it sees the same result as before.
- Every binding the specification states is checked, and each failure names which one: the response must be a three-part JWS whose algorithm is RS256, its signature must verify under the certificate in its own header, its nonce must match this registration's authenticator data and client data, the certificate must be issued to attest.android.com, and the chain must validate to one of the supplied roots. The algorithm is pinned and never read from the token, so a statement cannot select its own verification algorithm. The hostname is matched exactly against the certificate's subject alternative name, falling back to its common name only when it carries no alternative name at all; a name merely ending in attest.android.com does not pass. The chain goes through full path validation, so an expired or otherwise non-conforming certificate cannot pass on a signature alone. On success the result reports attestation type Basic with the embedded chain as its trust path.
- Device-integrity signals in the response (whether the device passed the compatibility test suite, the reported timestamp, the requesting package) are deliberately not gated on, because the specification does not make them part of attestation verification. They remain relying-party policy.

## v0.4.7 — 2026-08-08

One certificate now renders one distinguished-name string whichever parser read it. A C509 certificate's subject and issuer strings used to join their components without the separating space every other parser in the toolkit uses.

### Fixed

- A C509 certificate's subject and issuer strings now use the same spelling as every other parser in the toolkit: components separated by a comma and a space, which is what openssl prints for the same certificate. Previously the C509 parser omitted the space, so one certificate had two different rendered names depending on the parser that read it, and code comparing or logging them saw a difference where there was none. The two renderers are now checked against each other on a multi-component name, so the divergence cannot return.
- Where these strings are built now states what they are: a display form listing the components in the certificate's own order, escaped so that a comma inside a value cannot read as a separator between components. It is not an LDAP distinguished name, which reverses the component order and omits the space, and must not be passed to a directory client as one. Name comparison never used these strings and still does not.

## v0.4.6 — 2026-08-08

A C509 certificate now has one encoding where the specification defines one: nine alternative spellings that rebuilt a byte-identical X.509 certificate, so that a single signature covered all of them, are refused, and the encoder emits the spelling it accepts.

### Fixed

- An attribute value now carries the one spelling the specification assigns it. A text value of even length drawn only from the characters 0-9 and a-f is a byte string; a value in EUI-64 form is a tagged MAC address, 48-bit when it matches the FF-FE marker pattern and 64-bit otherwise; anything else is text. Each alternative spelling rebuilt the identical certificate, so the one signature over it covered them all. An empty value spelled as an empty byte string is refused for the same reason: it renders as the empty text, which already has a spelling.
- A name holding a single common name is the bare value, an extensions field holding only a key usage is the single integer, and an alternative name holding exactly one DNS name is the bare text. Each of these compact forms is the encoding the specification defines for that case, so the long form of the same value (an array of one pair, an array of two, an array of one entry) is now refused. The long form remains the encoding for every case that is not the single one: a name with two attributes, a key usage beside another extension, an alternative name with two entries.
- A certificate whose issuer is identical to its subject encodes that issuer as the CBOR simple value null, which the specification requires and which this toolkit previously wrote out in full. Both directions changed: the encoder emits the null, and a certificate that spells the issuer out instead is refused. The comparison is made on the certificate's own bytes, because the reconstruction rebuilds a null issuer from the subject: two names that merely compare equal would rebuild different bytes and break the signature over them.
- Algorithm parameters must be a complete element. An empty byte string is none, and it rebuilt the same algorithm identifier as the form that omits parameters entirely, giving one algorithm two encodings.
- The encoder walks the same rules it enforces on the way in, so a certificate it emits is one it reads back. Previously it wrote an even-length-hex attribute value as text (a spelling its own parser now refuses) and wrote a self-signed certificate's issuer out in full.

### Known limitations

- One redundancy remains because the specification permits it: a registered algorithm may be encoded either as its registry integer or as its object identifier, and both are accepted, so a certificate using one is byte-different from the same certificate using the other. Identify a certificate by the X.509 bytes it reconstructs; its C509 bytes are not a stable identity.

## v0.4.5 — 2026-08-08

A private key created outside this toolkit's own WebCrypto now signs and exports across the toolkit. A key from the platform's WebCrypto, or from a separately-installed copy of this toolkit, used to reach the crypto library as a key it could not read and fail with a type error that gave no reason.

### Fixed

- Certificate, CRL, CSR, CMS, attribute-certificate, OCSP, CMP and CRMF signing, together with pki.key.export and pki.jose.sign, accept a private key created by the platform's WebCrypto or by a separately-installed copy of this toolkit. Previously only a key this toolkit's own engine created would work; any other reached the crypto library as a key with no material behind it and failed with a type error naming an internal property, giving a caller who had followed the documented contract nothing to act on. Signing, private-key export, public-key export and secret-key signing are all covered, across EC, Edwards and RSA keys.
- A key that cannot be reached is refused with the reason and the ways forward (import it through this toolkit's WebCrypto, or pass it as DER); it is no longer reported as an argument of the wrong type. That covers a key created non-extractable, which no implementation can export, and one belonging to an implementation that keeps its material behind its own interface. The non-extractable refusal holds on every path, including for a key whose handle this process could otherwise read directly, so the flag means the same thing wherever the key came from. A non-extractable key this toolkit created is unaffected and still signs, since it is used in place and never exported.
- A key's permitted usages travel with it. Re-importing is the one moment that restriction could be widened, since the new key is created with the usages the operation needs. Every needed usage must therefore be present on the original first. Asking a verify-only key to sign is refused, which is what this toolkit's own engine already did for its own keys; the two now agree.
- pki.webcrypto.subtle refuses a key created by a different WebCrypto implementation with a typed fault that names where it came from, and distinguishes it from an argument that is no key at all. The specification leaves cross-implementation use undefined; every operation that reads key material (sign, verify, encrypt, decrypt, key derivation and encapsulation, wrapping, and export) previously let a bare type error escape from inside the crypto library instead. The counterpart public key of a key-agreement operation, which travels in the algorithm rather than as the key argument, is checked on the same footing.

## v0.4.4 — 2026-08-08

pki.schema.c509 encodes and decodes the RFC 3779 resource-delegation extensions: a C509 certificate carrying IP address blocks or AS identifiers now parses at all, where before it was refused outright, and its addresses ride the compact form the specification defines.

### Added

- pki.schema.c509 encodes and decodes the RFC 3779 IPAddrBlocks and ASIdentifiers extensions in their compact value form, together with their RFC 8360 v2 twins, which the specification encodes identically. Previously these extensions had no registry entry, so a conformant C509 certificate carrying one was refused with no fallback, and a C509 resource certificate could not be read at all. An address family carries its address-family identifier and optional sub-identifier, and its addresses as either the delta-coded integer form or the byte-string form; the prefix length rides the unused-bit count, so a prefix ending in zero bits survives exactly. Both directions reproduce the worked example published in the specification's own appendix, byte for byte.
- The specification fixes which address form applies, and the sender has no say: the byte-string form applies to a whole address family as soon as any one of its addresses exceeds eight octets, and the integer form applies otherwise. The decoder enforces that, so a family that used the wrong form, or mixed the two, is refused, which keeps a certificate from having two valid encodings.
- The compact form is used only for a certificate already in the canonical order RFC 3779 requires, at both levels. Within an address family the entries must be sorted, non-overlapping, and with any two contiguous entries already combined into one; the same three rules apply to AS identifiers. Across families, each address family may appear only once and they must ascend by their identifying octets, with a family carrying no sub-identifier preceding the one sharing its identifier. A certificate breaking any of these keeps its original bytes, because compacting it would give one resource set a second encoding when it already has a canonical one, and because such a certificate is one an independent validator rejects, so re-encoding it would quietly turn a refused certificate into an accepted one. An address wider than its family allows, or one whose declared unused bits are not zero, is likewise refused. Every rule is enforced in both directions, so the two halves of the codec accept exactly the same certificates.

### Fixed

- A certificate whose version is not v3 is now refused, with the reason given. Both C509 certificate types are defined over X.509 v3 and the encoding carries no version field, so a v1 or v2 certificate is outside the format; it previously fell through to the byte-exactness self-check, whose verdict reads as a defect in the encoder and says nothing about a certificate the format does not cover. A v3 certificate whose extensions field is omitted was and remains fully supported; the specification encodes that as an empty array.

## v0.4.3 — 2026-08-08

pki.tls encodes and decodes RFC 8879 compressed certificate messages (the largest payload a TLS handshake carries, and the one post-quantum chains grow by kilobytes) with the two-sided decompression bound the specification requires. Alongside it, SHAKE128 and SHAKE256 join the digest surface, which brings the Ed448 composite signature arm into service.

### Added

- pki.tls.decompressCertificate and pki.tls.compressCertificate encode and decode an RFC 8879 CompressedCertificate. Decompression applies the bound RFC 8879 sec. 5 requires on both sides: the decompressor is capped at the message's own declared uncompressed length, so a decompression bomb is refused as its output would exceed that declaration, before the memory is committed, and the recovered length must then equal the declaration exactly. A caller's own cap applies independently and can only tighten the limit, never raise it. An algorithm outside the registry, one this runtime cannot decompress, or one absent from the caller's advertised set is refused before any decompressor runs; an empty compressed body is a framing violation; and trailing bytes are refused, so one chain has exactly one encoding. compressCertificate decodes its own output before returning it, so a message this toolkit produces cannot be one this toolkit refuses, and refuses to emit one whose own framing would exceed the handshake limit.
- All three registered compression algorithms are implemented, and each is offered only where the running Node can decompress it safely. A decompressor is required to fault on a frame it could not finish; where one instead returns a short result and reports the whole input as consumed, a peer could cut a frame's tail and have the receiver process a prefix as if it were the entire message. Any algorithm whose decompressor behaves that way is dropped at startup and is then neither advertised nor accepted; it is never offered with a truncation it cannot detect. On the current long-term-support Node this drops zstd, leaving zlib and brotli; it returns by itself on a runtime that reports the fault.
- pki.tls.parseCertificateMessage decodes the RFC 8446 sec. 4.4.2 Certificate message itself, surfacing each entry's certificate DER exactly as it arrived, ready for pki.schema.x509.parse and never re-serialized, alongside its raw extensions and the certificate request context. The certificate type is negotiated by a separate extension and is not present in the message, so it is declared through an option and never inferred from the bytes. The number of entries is bounded: a message's byte ceiling does not limit how many it declares, since the smallest legal entry is six bytes, so a message well inside the framing limit could otherwise declare hundreds of thousands and exhaust memory. The cap matches the longest chain the path validator will accept, and is exactly one under a negotiated RawPublicKey type, which RFC 8446 sec. 4.4.2 requires.
- pki.webcrypto.subtle.digest computes SHAKE128 and SHAKE256, at the 32- and 64-byte lengths RFC 8702 sec. 4 fixes for message-digest use. The length follows from the name and is not the caller's to choose, so a digest cannot be squeezed to a non-conforming width. The extendable-output functions are a digest route only: the signature, MAC and key-derivation operations continue to refuse them with the same typed error as before.
- The composite signature arm id-MLDSA87-Ed448-SHAKE256 now verifies and signs. It was registered and parameter-guarded but failed closed as unsupported because its SHAKE256 pre-hash was unavailable; it is now checked byte-for-byte against the composite specification's own known-answer certificate, and both components must pass for the signature to be accepted. Sixteen of the eighteen arms now verify; the two remaining are the brainpool-curve arms.

### Changed

- pki.cms.sign and pki.cms.verify compute their message digests through the crypto engine; neither holds a private digest table any more. Behavior is unchanged; the digest algorithms a signer and a verifier accept are now defined in one place.

### Fixed

- pki.cms.decompress refuses a stream carrying bytes after the end of the compressed data. A decompressor stops at the end of the first complete frame and ignores whatever follows, so arbitrary bytes, or a second entire frame, could be appended and the same content still recovered. That gave one content unboundedly many encodings, so a digest over the compressed object no longer identified what it decompressed to. The whole octet string must now be exactly one frame, which is what the DER layer already required of its own encodings.
- An unusable hash is now refused when a key is created, and no longer at its first use. pki.webcrypto.subtle.importKey and generateKey recorded the requested hash without resolving it, so a name this engine cannot use produced a CryptoKey that failed only at its first sign, verify or wrap, after the caller had already paid for the key generation. The name is now resolved at the entry point, through the same table the operations use, so what a key can be created with and what it can be used with cannot diverge.

## v0.4.2 — 2026-08-07

A NumericString attribute value no longer shares distinguished-name identity with a printable or UTF-8 value of the same characters. That comparison decides name chaining, revocation-issuer matching and name constraints. Alongside it, several C509 name-encoding conformance fixes and a move to Node 24.19.0.

### Changed

- The supported Node floor moves to 24.19.0, the current long-term-support release. Nothing is transpiled, so the supported version is the version the source runs on; the release is verified against that runtime.
- pki.asn1.read.numericString reads a NumericString value, validated strictly to the digits and space the type permits. The shared string reader no longer accepts the type, so a caller that wants it asks for it by name.

### Fixed

- A NumericString attribute value no longer compares equal to a PrintableString or UTF8String attribute value carrying the same characters. RFC 5280 sec. 7.1 name comparison folds the directory-string types into one identity class, and NumericString is not one of them; because the previous release read it through the shared string reader, it entered that class and was treated as the same name by the comparison that decides certificate chaining, revocation-issuer matching and name-constraint evaluation. It now reads through its own reader and, as before, renders in the RFC 4514 hexadecimal form.
- A natively signed C509 certificate is no longer accepted with, or built carrying, a negative attribute-type integer. The sign of that integer exists only to reproduce the string type of an original X.509 encoding, which a natively signed certificate does not have, so all of its integers are non-negative (draft-ietf-cose-cbor-encoded-cert-20 sec. 3.1.4); the toolkit previously read such a certificate and could also emit one that a conformant implementation must reject.
- A country name or serial number attribute now keeps the string type its attribute integer's sign declares, and its restriction to the printable-string character subset is enforced on the characters instead. Both signs previously rebuilt the same certificate bytes, so two distinct compact encodings of one value produced one identical certificate under a single signature.
- The rendered distinguished-name string now escapes its values (RFC 4514 sec. 2.4), so an attribute value containing a comma can no longer read as though the name held several attributes, and a control byte can no longer reach a log line unescaped.
- An empty issuer name is now refused (RFC 5280 sec. 4.1.2.4 requires a non-empty issuer). It previously parsed and rebuilt a certificate that this toolkit's own certificate parser declines to load. An empty subject is still accepted; the profile pairs that with a subject alternative name, which this codec does not yet require.

## v0.4.1 — 2026-08-07

pki.schema.c509 encodes and decodes the compact subjectDirectoryAttributes value form: a C509 certificate's subject directory attributes ride their draft-20 registry integers (or unwrapped OIDs) with their directory-string values, so a conformant C509 implementation reads them.

### Added

- pki.schema.c509 encodes and decodes the compact value form for the subjectDirectoryAttributes extension (draft-ietf-cose-cbor-encoded-cert-20 sec. 3.3): a flat array of (attribute type, attribute values) pairs where each type is a sec. 8.6 registry integer (the sign selecting the directory-string type) or an unwrapped OID, and each values slot is a non-empty array holding the attribute's SET of one or more values: the string values for a registry-integer type, or the raw DER attribute values for an unwrapped-OID type. Both directions invert to the DER extnValue byte-for-byte, so a certificate carrying the extension is the specific compact shape a conformant C509 implementation reads, and an opaque DER byte string is no longer emitted for it. The encoder is guarded per attribute and per extension: an attribute whose value is not a directory string, or whose value SET mixes string types, uses the unwrapped-OID form for that attribute (keeping the rest of the extension compact); a value the compact form cannot represent falls the whole extension back to the unwrapped-OID byte-string form, where it survives byte-for-byte; and a malformed compact value fails closed with a typed C509Error.
- The OID registry gains the subjectDirectoryAttributes certificate-extension identifier (2.5.29.9), resolvable through pki.oid.byName / pki.oid.name.
- The ASN.1 codec reads NumericString (pki.asn1.TAGS.NUMERIC_STRING), the X.520 syntax of the x121Address and internationalISDNNumber directory attributes. It is validated strictly like every other string type: a value outside the digits-and-space set the type permits is rejected as malformed.

### Changed

- A C509 certificate carrying subjectDirectoryAttributes now encodes to, and decodes from, its compact CBOR value shape; an earlier release emitted the unwrapped-OID byte-string form. Both reconstruct the same DER, but the CBOR bytes differ, so re-encode any C509 produced by an earlier release.

## v0.4.0 — 2026-08-06

CRL issuance and verification, PKCS#12 build and open, attribute-certificate issuance, and the key-material lifecycle graduate to stable, and pki.schema.c509 adds the compact policyMappings and policyConstraints value forms. A C509 certificate's policy mappings and policy constraints now ride their specific draft-20 CBOR shape, readable by any conformant C509 implementation.

### Added

- pki.schema.c509 encodes and decodes the compact value forms for the policyMappings and policyConstraints extensions (draft-ietf-cose-cbor-encoded-cert-20 sec. 3.3): a policy mapping's issuerDomainPolicy and subjectDomainPolicy each ride the sec. 8.9 registry-integer / unwrapped-OID policy space the certificatePolicies extension uses (a policy mapping to or from the special anyPolicy is preserved, matching what a certificate's own decoder accepts), and a policy constraints value rides the fixed two-element [requireExplicitPolicy, inhibitPolicyMapping] array, each field a non-negative skip count or absent. Both directions invert to the DER extnValue byte-for-byte, so a certificate carrying either extension is the specific compact shape a conformant C509 implementation reads; an opaque DER byte string is no longer emitted. The encoder is guarded: a value the compact form cannot hold falls the whole extension back to the unwrapped-OID byte-string form, preserving it exactly; a malformed compact value (an empty or both-absent policy constraints, an odd-length or empty policy-mappings array, a policy mapping member that is not a two-policy pair, or an unregistered policy integer) fails closed with a typed C509Error.

### Changed

- pki.crl.sign / verify / isRevoked (RFC 5280 sec. 5), pki.pkcs12.build / open / verifyMac (RFC 7292 / RFC 9579), pki.attrcert.sign (RFC 5755), and the key-material lifecycle pki.key.encrypt / decrypt / export / import / generate / publicFromPrivate (PKCS#8 / RFC 5958, RFC 8018) graduate from experimental to stable. Their governing standards are settled and each is proven against an independent implementation in the integration harness (OpenSSL), or for the attribute-certificate format through the toolkit's own conformance-vector round-trip plus coverage-guided fuzzing. They are now covered by the stability contract: a breaking change to any of them ships only after a prior deprecation cycle, never silently in a minor (the published LTS support window itself takes effect at v1.0).
- A C509 certificate carrying policyMappings or policyConstraints now encodes to and decodes from its compact CBOR value shape; an earlier release emitted the unwrapped-OID byte-string form. Both reconstruct the same DER, but the CBOR bytes differ, so re-encode any C509 produced by an earlier release.

### Fixed

- The C509 encoder now bounds the basicConstraints path length and the inhibitAnyPolicy and policyConstraints skip counts to the same non-negative 31-bit range the toolkit's own certificate decoders enforce. A native C509 carrying one of these counts past that range now fails closed with a typed C509Error and no longer reconstructs a DER that an X.509 decoder, this toolkit's included, would then reject.

## v0.3.33 — 2026-08-05

pki.schema.c509 encodes and decodes the compact certificatePolicies value form. A C509 certificate's policy identifiers ride their draft-20 registry integers (or unwrapped OIDs) and their CPS-URI and UserNotice qualifiers ride the specific compact CBOR shape, so the certificate interoperates with a conformant C509 implementation.

### Added

- pki.schema.c509 encodes and decodes the compact value form for the certificatePolicies extension (draft-ietf-cose-cbor-encoded-cert-20 sec. 3.3): each policy identifier is a sec. 8.9 registry integer (the CA/Browser Forum validation levels, the RFC 3779 id-cp-ipAddr resource-certificate policies, and the GSMA SGP.22 id-rspRole roles), or an unwrapped OID for a policy outside the registry; each policy qualifier is a sec. 8.10 integer (id-qt-cps / id-qt-unotice) with its text, reconstructing the CPS pointer as a URI IA5String and the UserNotice as an explicit-text UTF8String. Both directions invert to the DER extnValue byte-for-byte, so a certificate carrying policies is the specific compact shape a conformant C509 implementation reads. The encoder is guarded: a UserNotice with a noticeRef, a non-UTF8String explicit text, or a policy-qualifier identifier outside the sec. 8.10 registry is not compact-representable and falls the whole extension back to the unwrapped-OID byte-string form with no lossy encoding; a malformed compact value (an empty UserNotice text, a control-byte CPS URI, an unregistered policy or qualifier integer) fails closed with a typed C509Error.
- The OID registry gains the CA/Browser Forum certificate-policy identifiers (domain-, organization-, individual-validated, ev-guidelines), the RFC 3779 id-cp-ipAddr-asNumber policies, the GSMA SGP.22 id-rspRole roles, and the RFC 5280 id-qt policy qualifiers (cps, unotice), resolvable through pki.oid.byName / pki.oid.name.

### Changed

- A C509 certificate carrying certificatePolicies now encodes to its compact CBOR value shape and decodes from it, where an earlier release emitted the unwrapped-OID byte-string form; both reconstruct the same DER, but the CBOR bytes differ, so re-encode any C509 produced by an earlier release.

## v0.3.32 — 2026-08-05

pki.schema.c509 encodes and decodes the compact general-name extension values: a C509 certificate's subjectAltName, issuer alternative name, name constraints, CRL distribution points, authority/subject information access, and the authority key identifier issuer form now ride their specific draft-20 CBOR shape, so a conformant C509 implementation can read them.

### Added

- pki.schema.c509 encodes and decodes the compact value forms for the general-name-bearing extensions defined by draft-ietf-cose-cbor-encoded-cert-20 sec. 3.3: subjectAltName and issuerAltName (a flat array of (general-name type, value) pairs, or the bare dNSName as CBOR text for a single host name), nameConstraints (the permitted and excluded GeneralSubtrees, with the RFC 9549 sec. 2.2 address-plus-prefix-length form for an iPAddress constraint), cRLDistributionPoints and freshestCRL (each distribution point's URI full name with optional reasons and CRL issuer, or a single bare URI as CBOR text), authorityInfoAccess and subjectInfoAccess (each access description as a sec. 8.11 registry integer or unwrapped OID plus its URI), and the authorityKeyIdentifier key-identifier / authority-cert-issuer / serial form. One shared GeneralNames codec drives them all, covering every general-name form the sec. 8.13 registry defines: rfc822Name, dNSName, directoryName, URI, iPAddress, registeredID, and otherName including the hardware-module-name (RFC 4108), SMTP UTF-8 mailbox (RFC 9598), and MAC-address specials. Each form inverts to the DER extnValue byte-for-byte in both directions, so a certificate carrying these extensions is the specific compact shape a conformant C509 implementation reads; it is no longer an opaque DER byte string. The encoder is guarded: it emits the compact form only when it decodes back to the exact DER value, so a general name outside the registry (an X.400 address, an EDI party name), a non-canonical value, or a value the compact form cannot hold falls the whole extension back to the unwrapped-OID byte-string form, so no partial or lossy value is encoded; a malformed compact value fails closed with a typed C509Error.
- The OID registry gains the id-on other-name type identifiers (hardware module name, SMTP UTF-8 mailbox, MAC address), the id-ad access-description methods (time stamping, CA repository, RPKI manifest / signed object / notify), and subject information access, resolvable through pki.oid.byName / pki.oid.name.

### Changed

- A C509 certificate carrying a general-name-bearing extension (subjectAltName, issuerAltName, nameConstraints, cRLDistributionPoints, freshestCRL, authorityInfoAccess, subjectInfoAccess, or the authorityKeyIdentifier issuer form) now encodes to, and decodes from, its compact CBOR value shape where an earlier release emitted the unwrapped-OID byte-string form; both reconstruct the same DER, but the CBOR bytes differ, so re-encode any C509 produced by an earlier release. A native C509 that carried a subjectAltName as a raw byte string under its extension integer, which is not a value form the draft defines, is now rejected.

## v0.3.31 — 2026-08-03

pki.schema.c509 encodes and decodes the compact per-extension value forms. A C509 certificate's keyUsage, basicConstraints, extended key usage, key identifiers, and other scalar extensions now ride in their specific draft-20 CBOR shape, which any conformant C509 implementation can read.

### Added

- pki.schema.c509 encodes and decodes the compact per-extension value forms defined by draft-ietf-cose-cbor-encoded-cert-20 sec. 3.3 for the common scalar extensions: subjectKeyIdentifier (the bare key id), keyUsage (a network-byte-order integer), basicConstraints (an integer: -2 for cA=false, -1 for cA=true with no path length, N for the path length), authorityKeyIdentifier (the bare key id, keyId-only form), extendedKeyUsage (an array of registry integers or unwrapped OIDs, the array omitted for a single purpose), inhibitAnyPolicy (an integer), OCSP No Check (CBOR null), and TLS Feature (an array of integers). Each form inverts to the DER extnValue byte-for-byte in both directions, so a C509 certificate carrying these extensions is the specific compact shape a conformant C509 implementation expects (draft-20 sec. 3.7 requires the specific form where one is defined), and no longer an opaque DER byte string. The encoder is guarded: it emits the compact form only when it decodes back to the exact DER value, so a non-canonical or unrepresentable extension value falls back to the unwrapped-OID byte-string form with no lossy encoding; a malformed compact value fails closed with a typed C509Error. The extended-key-usage integer shorthands cover the full draft-20 sec. 8.12 registry: the RFC 5280 purposes (serverAuth, clientAuth, codeSigning, emailProtection, timeStamping, ocspSigning, anyExtendedKeyUsage) plus the SSH (RFC 6187), Kerberos PKINIT (RFC 4556), CMC (RFC 6402), and Wi-SUN purposes; any purpose outside the registry encodes as an unwrapped OID.

### Changed

- pki.schema.c509's RDN-attribute (sec. 8.6) and extension (sec. 8.8) integer registries now match draft-ietf-cose-cbor-encoded-cert-20: authorityKeyIdentifier is extension integer 7, extendedKeyUsage 8, inhibitAnyPolicy 30, OCSP No Check 36, and TLS Feature 38; and the RDN attributes localityName, stateOrProvinceName, and streetAddress are integers 5, 6, and 7. A certificate carrying any of these attributes or extensions now encodes to, and decodes from, the draft-20 integers and compact value shapes, so it interoperates with a conformant C509 implementation; re-encode any C509 produced by an earlier release, whose integers and per-extension value shapes differ.

## v0.3.29 — 2026-08-02

The pki.acme client rounds out its RFC 8555 / RFC 9773 surface: pre-authorize an identifier with client.newAuthz, choose among alternate issuance chains in client.downloadCertificate, and schedule renewal from the CA's ARI window with client.renewalWindow.

### Added

- client.newAuthz(identifier) pre-authorizes a single identifier ahead of placing an order (RFC 8555 sec. 7.4.1): it POSTs the identifier to the directory's newAuthz resource (kid-signed) and returns { authorization, url } for the created authorization, normally pending, or an already-valid one when the CA has out-of-band authorization for the identifier. A wildcard identifier is refused before any request (pre-authorization of a wildcard is not defined), an unadvertised newAuthz resource fails closed, a 201 without a Location fails closed, and the returned authorization is validated to name exactly the identifier requested and to be a non-wildcard authorization the flow can proceed with. One that names a different identifier, is marked as a broader wildcard grant, or is in a terminal failed state is rejected.
- client.downloadCertificate(url, opts?) gains selectChain + maxAlternates to choose among the alternate issuance chains a CA offers (RFC 8555 sec. 7.4.2, RFC 8288 Link). Without a selector it returns the primary chain and now also alternates, the resolved URLs of every Link rel="alternate" the certificate response advertised. With selectChain, it evaluates the primary chain first, then each alternate in header order, and resolves to the first chain the predicate accepts (selectChain receives { certificate, chain, certificates }); none accepted fails closed. The alternate Link header is untrusted: it is parsed strictly against RFC 8288 (rel matched as a whole token, case-insensitively; a malformed header or a non-https target fails closed), the extra signed fetches are bounded by maxAlternates (default 8, over-budget fails closed), duplicate resolved URLs are de-duplicated, and an alternate whose end-entity certificate differs from the primary's is rejected; it does not substitute for the primary. Each alternate is fetched by the same POST-as-GET path, inheriting the media-type, size, and strict-chain-parse gates.
- client.renewalWindow(certDer, opts?) turns the CA's ARI renewal window into a scheduling decision (RFC 9773 sec. 4.2 / 4.3). It composes the unauthenticated renewalInfo GET and selects a uniform-random instant within the CA's suggested window, bounded by the certificate's own expiry so the chosen time is never after notAfter, so many clients do not renew at the same edge. An injectable random and clock make the decision deterministic and let a caller ask 'renew as of time T?'. It returns { suggestedWindow, selectedTime, renewNow, retryAfterSeconds, explanationURL }, where renewNow is set when the selected instant is already in the past. It refuses before any request for a certificate already past its notAfter (nothing to renew) or one the caller marks with replaced: true (already superseded), and retryAfterSeconds always carries a poll delay: the CA's Retry-After clamped to [60s, 24h], or a sensible default when the CA omits it. Pass a prior result back as opts.previous to reuse its selectedTime while the CA's window is unchanged (RFC 9773 sec. 4.2), so a client that refreshes ARI on each poll keeps one stable renewal instant and does not re-randomize it. The helper returns the decision as data; it never sleeps or schedules on a background timer.

### Changed

- client.renewalInfo(certDer) now refuses an already-expired certificate before issuing the unauthenticated RenewalInfo GET (RFC 9773 sec. 4.3: a client MUST NOT check a certificate's RenewalInfo after it has expired), throwing acme/certificate-expired, the same pre-fetch expiry gate renewalWindow applies.
- pki.acme.client now rejects a server-provided URL whose host is an IPv4-address form (hex, octal, decimal, or shorthand) that the WHATWG URL parser would coerce to a different, often loopback or internal, address. The account-signed JWS url (RFC 8555 sec. 6.4) must name the exact authority the request connects to, so such a URL can no longer steer an authenticated request to an unintended host (SSRF hardening).

## v0.3.28 — 2026-08-01

pki.est gains its remaining RFC 7030 network verbs: request a server-generated key pair with pki.est.serverkeygen, fetch the CA's CSR-attributes policy with pki.est.csrattrs, and authenticate with HTTP Digest as an alternative to HTTP Basic.

### Added

- pki.est.serverkeygen(baseUrl, csr, opts?) requests a server-generated key pair + certificate (RFC 7030 sec. 4.4): it POSTs the CSR (application/pkcs10, identical encoding to simpleenroll) to /.well-known/est/serverkeygen and returns { certificates, privateKey } for a cleartext PKCS#8 PrivateKeyInfo key part, { certificates, encryptedKey } for a CMS EnvelopedData key part (surfaced structurally, never decrypted), or { retry, retryAfterSeconds, retryAfterDate } on a 202. The certificates are returned raw (no leaf is selected: the CA generated the key, so the issued certificate carries the generated public key; the CSR key was a throwaway). A cleartext key is bound to its certificate before it is surfaced: the delivered private key's public half must match exactly one returned certificate, so a key mis-associated with the returned certificate set is refused. Whether the key part must be encrypted, and to which recipient, is derived from the CSR's DecryptKeyIdentifier (a symmetric key-encryption key) or AsymmetricDecryptKeyIdentifier (an asymmetric key) attribute; the recipient mechanism is preserved and required to match the RecipientInfo arm, so a symmetric KEK recipient never satisfies an advertised asymmetric key (or vice versa) merely because the identifier bytes coincide. An opts value that contradicts the CSR is refused, and a cleartext key delivered where the CSR requested encryption is refused, as is an encrypted key delivered where the CSR advertised no decryption key to open it (an unusable, unsolicited credential). The delivered key's channel must negotiate a confidentiality-bearing cipher (a NULL / anonymous / EXPORT suite is refused). https-only, explicit-anchor, and the full redirect / auth / budget machinery of the enrollment verbs apply.
- pki.est.csrattrs(baseUrl, opts?) fetches the CA's CSR-attributes policy (RFC 7030 sec. 4.5, RFC 9908): a 200 application/csrattrs body is parsed and returned as { available: true, attrs, plan }, where plan is the enroll-attribute plan the caller builds its next CSR from; a 204 or 404 is { available: false } (a valid "CSR Attributes Response not available"); an empty CsrAttrs is a complete empty policy. The verb never applies attributes to a CSR itself. Server authentication is not required for this policy GET, but a 401 is honored so the auth path stays available.
- HTTP Digest access authentication (RFC 7616) is available on every EST verb as an alternative to HTTP Basic via opts.auth = { scheme: "digest", username, password }. SHA-256 and SHA-512-256 are supported; MD5 and MD5-sess are refused unless opts.auth.allowMD5 is set, and a legacy no-qop (RFC 2069) challenge is refused unless opts.auth.allowLegacyQop is set. Among multiple offered challenges the most secure usable one is chosen. A challenge this client cannot answer under its policy (an unsupported or disallowed algorithm, or a qop mode it does not accept) never shadows a lower-ranked usable one, so the client authenticates on an offer it can actually answer; when no offer is usable it fails closed and names the specific reason, with no downgrade to a weaker scheme. A server stale=true re-challenge is answered under a bounded opts.auth.maxStaleRetries budget. The response is scoped to the challenge's protection space: within an origin it is preemptively reused only for the URIs the challenge's domain directive covers (a quoted directive; a malformed unquoted one is refused and never silently widened; an absolute-URI entry is matched by its authority as well as its path, so an entry naming a different host never widens the scope to this one; the query is kept in the comparison, so an entry scoped to one query does not cover a different one). A same-origin resource outside that scope is authenticated afresh under a bound, classified by whether the request actually carried a credential, so a resource sent unauthenticated is never mistaken for a rejected one; it is neither sent the first realm's response nor blocked outright. A non-ASCII username under a charset=UTF-8 challenge is carried in the RFC 5987 username* extended form (percent-encoded UTF-8). The legacy quoted field would reach a server as ISO-8859-1. A non-ASCII realm's incoming header octets are hashed unchanged, so a UTF-8 realm contributes the same octets the server used and the response matches an RFC 7616 server. As with Basic, the credential is answered only on the origin the caller authenticated to: never sent to a redirected origin, and never as a silent Basic downgrade of a Digest challenge.

## v0.3.27 — 2026-07-31

pki.cmp.session drives a full CMP certificate enrollment end to end: build, transfer, and verify every leg of an ir/cr/kur/p10cr exchange, with every response protection-checked before its body is read.

### Added

- pki.cmp.session(opts) returns a stateful CMP enrollment session; session.enroll(request) drives an RFC 9810 ir / cr / kur / p10cr exchange to completion and returns a terminal verdict { outcome, certificate, chain, status, trusted, confirmed, implicitConfirm, transactionID, polls, transcript }. Every response is protection-verified (pki.cmp.verify) and bound to the transaction by transactionID and a fresh-senderNonce / echoed-recipNonce chain before its body is read, and is advanced only if its signer is trusted (chains to a supplied anchor, or the shared secret matches); a waiting status is polled under a bounded pollReq/pollRep loop; a grant is confirmed by a certConf/pkiConf handshake unless implicit confirmation was granted. opts.key + opts.cert select signature protection (with opts.trustAnchors REQUIRED to authenticate the CA's response signer, opts.intermediates an extra chain pool) or opts.mac selects PBMAC1; opts.transport / opts.tls / opts.timeout / opts.maxResponseBytes configure transfer; opts.maxPolls / opts.maxTotalWait / opts.sleep bound the poll loop; opts.sender / opts.recipient / opts.implicitConfirm / opts.extraCerts tune the request. opts.acceptCert is an acceptance policy consulted before confirmation: it can inspect and veto a grantedWithMods certificate the CA changed, sending a rejecting certConf and returning outcome rejected with the certificate still surfaced. A MAC-protected ir / cr / kur must carry the requested key's private half as the request-arm key so the CRMF proof of possession is signed (a signature session reuses its protection key). A verified rejection or error, or an exhausted poll budget, is a terminal outcome; a tampered, unverifiable, untrusted, or nonce-mismatched response is a typed CmpError throw. RFC 9810 sec. 5.1.1 / 5.2.3 / 5.3.4 / 5.3.18 / 5.3.22, RFC 9811, RFC 9483.

## v0.3.26 — 2026-07-30

pki.cmp.verify checks the protection on an incoming CMP PKIMessage. It verifies a signature or PBMAC1 MAC over the exact protected bytes, and can chain the signer certificate to a trust anchor.

### Added

- pki.cmp.verify(message, opts) verifies the protection on an incoming CMP PKIMessage: a DER Buffer, a PEM CMP block, or an already-parsed pki.schema.cmp.parse result (the protection is always recomputed from the parser's raw header/body wire slices, so a mutated display field on a parsed object cannot desync the crypto). Signature protection is verified through the shared certification-path signature engine; PBMAC1 protection is recomputed from opts.sharedSecret and compared in constant time. opts.signerCert / opts.trustAnchors / opts.intermediates / opts.time drive signer-certificate resolution (opts.signerCert, the message senderKID, or RFC 9483 extraCerts[0]) and full out-of-path certificate validation; opts.transactionID / opts.expectRecipNonce add opt-in response-echo checks; opts.maxIterations bounds the PBKDF2 work. The result is a fail-closed verdict { valid, trusted, protectionType, protectionAlg, signer, transactionID, senderNonce, recipNonce, header, body } carrying a typed cmp/* code on rejection; a malformed message or a flavor/credential mismatch throws a typed CmpError. RFC 9810 sec. 5.1.3, RFC 9481 sec. 3 / 6.1.2, RFC 9579, RFC 9483 sec. 3.1 / 3.2 / 3.3.

### Fixed

- The EST and ACME clients (pki.est / pki.acme) now reset the origin-specific tls.servername (SNI) on a cross-origin redirect / request even when no mTLS client certificate is set, so the trusted host's SNI is never sent to a different origin. A caller's tls.checkServerIdentity pin is retained across the origin boundary and re-evaluated against the redirected host, so a certificate / SPKI pin keeps applying and is never silently bypassed by dropping the callback.

## v0.3.25 — 2026-07-26

pki.path.build can now fetch a missing intermediate over the network: opt in with `fetchAia` and it discovers the issuer from a certificate's AIA caIssuers URL, so a chain with a gap in the supplied pool still builds.

### Added

- pki.path.build accepts opts.fetchAia: true to discover a missing intermediate from a certificate's AIA caIssuers URL (RFC 5280 sec. 4.2.2.1) over pki.transport, explored as a lazy fallback only after the local candidate pool is exhausted (RFC 4158 sec. 7.2 local-before-remote), so a build the pool can complete never touches the network. The result gains aiaFetches (the count of network GETs). opts.transport injects the transport for offline use; opts.tls carries the TLS trust for the AIA host (distinct from opts.trustAnchors); opts.maxAiaFetches / opts.maxAiaPerCert / opts.aiaTimeout / opts.maxResponseBytes bound the fetch. Off by default; the default build is byte-identical offline. RFC 5280 sec. 4.2.2.1, RFC 4158 sec. 6.3 / sec. 8.1.
- pki.inspect renders the authorityInfoAccess extension (RFC 5280 sec. 4.2.2.1) as the CA Issuers and OCSP access descriptions with their URLs, where it used to print a hex dump.

### Changed

- The AIA fetch is fail-closed and SSRF-bounded: an http/ldap/ftp/file/mailto or non-URI caIssuers accessLocation, or an id-ad-ocsp access method, is never fetched (no socket); a destination that is, or that resolves to, a private, loopback, or link-local address is refused (the checked address pinned for the connection), so an untrusted certificate cannot drive an authenticated GET to an internal service by IP literal or by hostname; a total fetch budget silently caps fetching (never a throw that denies a buildable path); a per-certificate URL cap (maxAiaPerCert:0 disables per-certificate fetching outright), a build-wide URL dedupe on the normalized URL, a response-size cap, and a per-response certificate-count cap bound the work; no redirect is followed. Every fetch fault (a transport error, a non-200, an oversize or non-certificate body) is a silent skip, so an unreachable or hostile AIA endpoint never fails a build that the pool could still complete.

## v0.3.24 — 2026-07-26

pki.smime.verify / decrypt can now recognize a legacy (RFC 8551) header-protected message. Opt in with `legacyHeaderProtection` and the real headers of an older `message/rfc822`-wrapped message are surfaced, safely separated from the authenticated header set.

### Added

- pki.smime.verify and pki.smime.decrypt accept opts.legacyHeaderProtection: true to detect a legacy RFC 8551 header-protected message (RFC 9788 sec. 4.10): a signed or encrypted payload that is a bare message/rfc822 wrap with no hp= parameter. On a precise match the inner message's Non-Structural headers are surfaced under headerProtection.legacy = { headers, mode, fromMismatch, confidential }, with the mode inferred from the envelope and an encrypted message's confidential set computed against the visible outer headers. RFC 9788 sec. 4.10.1 / sec. 4.10.2, RFC 8551.
- headerProtection.legacy is null on every verify / decrypt result unless a legacy message was detected via legacyHeaderProtection. The inferred set is intentionally kept separate from the authenticated protectedHeaders (which stays null) and from present (which stays false), since a legacy message is indistinguishable from a forwarded message/rfc822. A consumer keying trust off present/protectedHeaders is therefore never misled by the opt-in heuristic, and consuming headerProtection.legacy.headers is an explicit, fromMismatch-checkable choice.

### Changed

- Detection is opt-in and safe-by-default. Without legacyHeaderProtection the behavior is unchanged: a legacy-form message reads as protectedHeaders: null, present: false, legacy: null (never mis-authenticated). With the option set, a message that is not precisely identified (an ordinary forwarded message/rfc822 that fails a condition, an inner part that is itself a signed/encrypted layer, an inner part declaring hp=, or a part with a duplicate Content-Type) reports legacy: null. The signed-and-encrypted legacy form (RFC 9788 Appendix C.3.17) surfaces as clear via the caller's re-verify step, a documented limitation of the non-recursive layered API.

## v0.3.23 — 2026-07-26

pki.pkcs12.open now reads legacy PKCS#12 stores: it decrypts the RFC 7292 Appendix C 3DES and RC2 bags an `openssl pkcs12 -legacy` (and NSS) store uses, so an older .p12/.pfx now opens.

### Added

- pki.pkcs12.open decrypts the RFC 7292 Appendix C legacy PBE bags: pbeWithSHAAnd3-KeyTripleDES-CBC, pbeWithSHAAnd2-KeyTripleDES-CBC, pbeWithSHAAnd128BitRC2-CBC, and pbeWithSHAAnd40BitRC2-CBC. An `openssl pkcs12 -legacy` or NSS store, whose default key bag is 3DES and default cert bag is 40-bit RC2, now opens where before it was refused. The cipher key and IV are derived with the PKCS#12 Appendix B method over the BMPString+NULL password; a wrong password is caught by the MAC gate (or, for a MAC-less store, is the uniform pkcs12/decrypt-failed). The iteration count is DoS-capped before the key derivation runs. RFC 7292, RFC 2268, RFC 8018.
- An in-tree RFC 2268 RC2-CBC (lib/rc2.js) fills the gap left by OpenSSL 3.x moving RC2 to its legacy provider (Node's crypto can no longer decrypt it). It is own code with no new runtime dependency, pinned to the RFC 2268 Section 5 known-answer vectors and cross-checked against real OpenSSL -legacy RC2-40 and RC2-128 stores.

### Changed

- The legacy RC4 PBE schemes (pbeWithSHAAnd128BitRC4 / pbeWithSHAAnd40BitRC4) remain refused, now with a message that names the scheme and the remediation (re-export the store under AES-256-CBC or PBE-SHA1-3DES).

## v0.3.22 — 2026-07-26

S/MIME header protection ships: cover the message headers (Subject, From, To, ...) under the CMS signature or encryption with pki.smime, RFC 9788.

### Added

- pki.smime.sign / pki.smime.encrypt gain opts.protectHeaders (RFC 9788 header protection) with opts.headers, an object { Name: value } or an array [{ name, value }] of the Non-Structural fields to protect (Subject / From / To / Date / ...). Signed protection marks the payload hp="clear" and copies the fields to the outer display headers; encrypted protection marks it hp="cipher", inlines the real values inside the ciphertext, emits the Header-Confidentiality-Policy-processed outer copies, and embeds the authenticated HP-Outer records that document which fields were left visible outside. opts.hcp selects "hcp_baseline" (default: obscure Subject to [...], remove Comments/Keywords) or "hcp_no_confidentiality". The CMS crypto is unchanged, so any signer / recipient algorithm carries through. RFC 9788.
- pki.smime.verify / pki.smime.decrypt return protectedHeaders (the authenticated inner header set, or null when the message is not header-protected) and headerProtection { present, mode, fromMismatch, confidential }. The inner protected headers are surfaced distinctly from the untrusted outer headers, fromMismatch flags an outer From that disagrees with the protected one, and confidential lists the fields the composer kept end-to-end confidential, computed from the authenticated HP-Outer records so a caller can reply or forward without leaking them. A payload declaring hp that is malformed, carries an invalid value, or contradicts the cryptographic envelope (a signed message claiming hp="cipher") fails closed with smime/bad-header-protection; there is no silent downgrade. RFC 9788.
- Every MIME header field pki.smime emits routes through a fail-closed header-field guard: a CR / LF / NUL in a field value, or a field name outside RFC 5322 ftext, is rejected with smime/bad-header, so a caller-supplied Subject can never inject a Bcc header or split the message (CWE-93).

## v0.3.21 — 2026-07-26

A Certificate Transparency log-list live-fetch client ships. pki.ct.fetchLogList fetches and verifies the CT log list over HTTPS before trusting a single log.

### Added

- pki.ct.fetchLogList(opts) fetches the Certificate Transparency log list live and returns the trusted-log set only after the detached signature verifies against the caller-pinned distributor key. It GETs opts.url (the log_list.json) and the detached opts.sigUrl (the log_list.sig, by default opts.url with a .json path suffix rewritten to .sig) over the shared pki.transport (or an injected opts.transport), verifies pki.ct.verifyLogListSignature over the raw JSON bytes against opts.signerKey, and only on a valid signature ingests the same bytes through pki.ct.parseLogList, returning { logs, byLogId, version, timestamp, raw, status, contentType, tls }. No baked-in vendor URL and no baked-in key (both are caller-pinned); explicit TLS trust (an anchor set or an opts.tls.useSystemStore opt-in, rejectUnauthorized always on); each GET is size-capped before verify/parse; every fetch / verify / parse failure is a typed CtError. RFC 6962.
- pki.ct.parseLogList now also returns the document's version (a string or null) and timestamp (the parsed log_list_timestamp as a Date, or null when absent/unparseable). That is the freshness surface a caller polices, read leniently from the same document. Existing callers of the { logs, byLogId } shape are unaffected.

## v0.3.20 — 2026-07-25

PKCS#12 public-key privacy ships: encrypt a store's contents to a recipient public key with pki.pkcs12.build/open, plus a webcrypto RSA algorithm-name fix.

### Added

- PKCS#12 public-key privacy (RFC 7292 sec. 3.1): pki.pkcs12.build encrypts a SafeContents to recipient public keys, either through per-safeContents recipients: [{ cert }, ...] (certificate recipients only) with an optional contentEncryptionAlgorithm (aes-128|192|256-cbc, default 256; GCM/AEAD rejected), or through the opts.recipientCerts convenience that envelopes the cert + key. It emits an id-envelopedData ContentInfo via pki.cms.encrypt, so every certificate recipient type (RSA-OAEP, ECDH P-256/384/521, X25519, X448, ML-KEM) and multiple recipients per safe carry through. Privacy is independent of the integrity mode; combining a password (encrypt) and recipients on one safe is rejected, as is a non-certificate (password/KEK) recipient.
- pki.pkcs12.open gains opts.recipientKey (+ opts.recipientCert or recipientIndex) to decrypt an id-envelopedData safe via pki.cms.decrypt, after the MAC / SignedData integrity gate. The recipient key is a privacy credential only; it is never a MAC key, signer, or bag password. A wrong key, a tampered envelope, or a decrypt that yields non-SafeContents bytes all collapse to a uniform pkcs12/decrypt-failed (oracle-free); an enveloped safe with no recipientKey is pkcs12/no-recipient-key.

### Fixed

- pki.webcrypto now emits the WebCrypto-registered casing on a CryptoKey's algorithm.name for RSASSA-PKCS1-v1_5 (lowercase v), matching the standard and the mixed-case Ed25519 / Ed448 it already emitted, so the toolkit's own RSASSA-PKCS1-v1_5 CryptoKey can be passed as an x509 signer key. The x509 signer's algorithm-name match is now ASCII-case-folded as well (WebCrypto algorithm names are case-insensitive), so a CryptoKey from any source with equivalent casing is accepted.

## v0.3.19 — 2026-07-25

The CMP HTTP transfer client ships: pki.cmp.transfer carries a protected PKIMessage to a CMP endpoint over the shared node:https transport (RFC 9811).

### Added

- pki.cmp.transfer(url, message, opts) is the RFC 9811 HTTP transfer verb: POST a DER (or PEM) PKIMessage over the shared pki.transport and return the parsed response { response, responseBytes, status, contentType, tls }. The message is sent verbatim so its message-layer protection is preserved, and the response is classified fail-closed: HTTP 200 with an application/pkixcmp body is parsed; another 2xx is rejected (RFC 9811 requires 200); a 3xx is not followed; a 4xx/5xx carrying a CMP error PKIMessage forwards that integrity-protected verdict with the HTTP status surfaced as data, while a 4xx/5xx with no CMP body is an error. Protection is surfaced but not verified; the caller checks it. Composes pki.cmp.build + pki.schema.cmp.parse over pki.transport; the default transport is https-only and refuses an unpinned server.
- Use pki.cmp.wellKnownUrl(base, opts) to build an RFC 9811 sec. 3.4 /.well-known/cmp request-URI, optionally with a { label, operation } path. Each label/operation is a single safe path segment; a base carrying a query or fragment, or a segment containing a separator or dot-segment, is refused so the resource cannot be silently retargeted.

### Changed

- pki.x509.sign now accepts a subjectAltName iPAddress entry as a dotted-quad IPv4 or colon-hex IPv6 string (packed to its 4- or 16-octet network form internally) in addition to a pre-packed Buffer, matching the string ergonomics of dNSName and uniformResourceIdentifier. This applies to every GeneralName consumer (certificates, CRLs, CMP, attribute certificates).
- extendedKeyUsage and certificatePolicies now accept a raw dotted-decimal OID string directly, in addition to a registered purpose/policy name, so an unregistered KeyPurposeId or private policy OID (a BIMI VMC purpose, a document-signing EKU, a vendor-specific purpose) can be supplied inline without first calling pki.oid.register or hand-encoding the extension. A token that is neither a registered name nor a well-formed dotted OID still fails closed.

## v0.3.18 — 2026-07-25

The ACME client ships. pki.acme drives the full RFC 8555 certificate-issuance flow over the shared node:https transport.

### Added

- pki.acme.client(directoryUrl, opts) is a stateful RFC 8555 ACME client over the shared pki.transport. newAccount / newOrder / getOrder / getAuthorization / getChallenge / respondToChallenge / finalize / pollOrder / pollAuthorization / downloadCertificate drive the issuance flow; revokeCert (RFC 8555 sec. 7.6, account-key or certificate-key signed), keyChange (sec. 7.3.5 account key rotation), deactivateAccount / deactivateAuthorization, and renewalInfo (ARI, RFC 9773) round out the account and certificate lifecycle. Signs every request with the account key (opts.accountKey / accountJwk / alg); reads are POST-as-GET; a problem+json response surfaces as a typed acme/server-problem.
- Fail-closed transport defaults for the client: HTTPS is required for the directory URL and every server-returned URL (acme/insecure-url), the default transport rejects a connection with no explicit trust anchor unless tls.useSystemStore is set (acme/no-trust-anchors), each JWS carries a fresh single-use nonce with a bounded badNonce retry, the poll loop is bounded by maxPolls and a total-wait budget and sleeps on a Retry-After via an injectable sleeper, and every response body is capped (acme/response-too-large).

### Fixed

- The EST enrollment client now measures a string response body as UTF-8 (the width it is decoded at), so a non-ASCII body cannot undercount its byte length and slip past the response-size cap. The built-in node:https transport was unaffected (it returns raw bytes); this hardens a custom injected transport that returns string bodies.

## v0.3.17 — 2026-07-24

Refresh two development-only tooling dependencies to clear newly-disclosed advisories.

### Security

- Refresh the development/fuzzing-only brace-expansion (5.0.7 -> 5.0.8, GHSA-mh99-v99m-4gvg) and tar (7.5.19 -> 7.5.22, GHSA-r292-9mhp-454m) tooling dependencies to versions clear of two newly-disclosed advisories. Both are used only by the development and fuzzing harnesses and are never part of the published package (the toolkit has zero runtime dependencies), so installed contents are unchanged.

## v0.3.16 — 2026-07-24

The EST enrollment client ships: pki.est fetches CA certificates and enrolls certificates over the wire (RFC 7030), on a new shared node:https transport.

### Added

- pki.est.cacerts(baseUrl, opts?), pki.est.simpleenroll(baseUrl, csr, opts?), and pki.est.simplereenroll(baseUrl, csr, opts?) are the thin RFC 7030 client verbs over pki.transport. cacerts returns the raw, unordered CA certificate set; simpleenroll submits a PKCS#10 CSR (a DER Buffer or PEM) and returns the issued certificate (chosen by public-key match) with its chain; simplereenroll additionally requires opts.oldCert and enforces the byte-identical Subject + SubjectAltName re-enroll check before the request. A 202 is surfaced as { retry, retryAfterSeconds } and never slept on. Trust is fail-closed: an https URL and an explicit opts.tls.anchors (or opts.tls.useSystemStore) are required, HTTP Basic credentials are answered only after the server is authenticated and are dropped on a cross-origin redirect, and a downgrade, redirect loop, oversized response, or unmatched issued certificate each fails closed with a typed est/* error.
- The enrollment clients drive pki.transport, a shared, fail-closed node:https transport. pki.transport.https(defaults) returns a transport(request) -> Promise<{ status, headers, body }>. It is the toolkit's only socket: rejectUnauthorized is always on with no disable path, an explicit trust anchor or a system-store opt-in is required, TLS is floored at 1.2, the response body is bounded while it streams (LIMITS.HTTP_MAX_RESPONSE_BYTES, tightenable downward), and connect/read is bounded by a timeout. It carries no HTTP or protocol semantics (status, content-type, redirect, and authentication decisions live in the message layer), so it is reused verbatim across enrollment protocols. errors.TransportError is its default fault type; a protocol client may parameterize it to surface domain codes.

## v0.3.15 — 2026-07-24

PKCS#12 public-key integrity is produced and verified (RFC 7292 sec. 4).

### Added

- pki.pkcs12.build produces a public-key-integrity PKCS#12 store (RFC 7292 sec. 4). With opts.integrity { mode: 'public-key', signer: { cert, key, digestAlgorithm?, pss? } | signers: [ ... ], sid?, signingTime?, certificates? } it wraps the AuthenticatedSafe in a CMS SignedData whose id-data eContent is the byte-exact AuthenticatedSafe, signed by any pki.cms.sign signer algorithm (RSA PKCS#1 v1.5 / RSASSA-PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, composite ML-DSA), with no MacData. Combining opts.mac with public-key integrity, or building with no signer, is a config-time pkcs12/bad-integrity-mode or pkcs12/bad-input. Privacy is unchanged: opts.password still PBES2-encrypts the bags.
- pki.pkcs12.open verifies a public-key-integrity store. It runs pki.cms.verify over the store's CMS SignedData authSafe before decrypting any bag, the same integrity gate the MAC provides for password mode, and returns nothing on a failure (pkcs12/signature-invalid). The result bundle gains signers, the per-signer verdict [{ ok, sid, cert }] (null in password / MAC-less mode); the signer certificate is surfaced but never chained to a trust anchor; anchoring it is the caller's pki.path.validate step. opts.signerCerts supplies the signer certificate for a store built with certificates: false. The bags then decrypt under the caller password exactly as in password mode (privacy is independent of integrity); a wrong bag password is the uniform pkcs12/decrypt-failed.

## v0.3.14 — 2026-07-23

CMS AuthenticatedData is produced and verified (RFC 5652 sec. 9).

### Added

- pki.cms.authenticate(content, recipients, opts) produces a CMS AuthenticatedData (RFC 5652 sec. 9): cleartext content authenticated by an HMAC-SHA-256/384/512 MAC, with the fresh MAC key wrapped for each recipient through the same RecipientInfo model pki.cms.encrypt uses (key-transport RSAES-OAEP, key-agreement ECDH/X25519/X448, ML-KEM ori, password pwri, key-wrap kekri). By default it MACs the authenticated attributes (content-type + message-digest of the content) re-tagged to the EXPLICIT SET OF (sec. 9.2); opts.authenticatedAttributes false MACs the content octets directly (id-data only). opts.macAlgorithm selects the HMAC hash and opts.digestAlgorithm the message-digest hash. Returns a DER Buffer or, with opts.pem, a PEM string. RFC 5652 sec. 9, RFC 2104, RFC 4231.
- pki.cms.decrypt verifies a CMS AuthenticatedData. It recovers the MAC key through the matching RecipientInfo, recomputes the HMAC over the exact RFC 5652 section 9.2 preimage, and, when authenticated attributes are present, independently recomputes digest(content) and confirms it equals the message-digest attribute (section 9.3, do not trust the originator's digest), before releasing the content with authenticated true and macAlgorithm / digestAlgorithm in place of contentEncryptionAlgorithm. Every secret-dependent failure (a wrong recipient key, a forged or tampered MAC, a message-digest mismatch) collapses to the one uniform cms/decrypt-failed verdict, so a MAC failure is indistinguishable from a key-unwrap failure and leaks no unwrap-success bit. A weak or unknown macAlgorithm (HMAC-SHA-1) is refused with a distinct cms/unsupported-algorithm before any key step.

## v0.3.13 — 2026-07-23

CMS gains countersignatures and unsigned attributes (RFC 5652 sec. 11.4).

### Added

- pki.cms.countersign(cms, signers, opts) adds RFC 5652 section 11.4 countersignatures to a CMS SignedData. Each countersigner is the same { cert, key, digestAlgorithm?, pss? } descriptor pki.cms.sign takes (RSA, RSASSA-PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, or composite ML-DSA), and its signature covers the countersigned SignerInfo's signature octets under the section 11.4 preimage: message-digest bound to those octets, content-type omitted. opts.signerIndex selects which primary signer(s) to countersign (an index, an array, or 'all'), opts.countersignatureOf countersigns an existing countersignature (a nested countersignature), opts.signedAttributes false signs the target signature directly, and the countersigner certificate is embedded by default. The countersigned SignedData's original bytes are preserved so the primary signature verifies unchanged, and multiple countersignatures on one signer land as multiple values of the one id-countersignature attribute. Returns a DER Buffer or, with opts.pem, a PEM string. RFC 5652 sec. 11.4.
- pki.cms.verify surfaces countersignatures and unsigned attributes per signer. Each res.signers[i] carries countersignatures and unsignedAttrs. countersignatures is an array of per-countersignature verdicts { ok, sid, cert, digestAlgorithm, ... }, each verified over the exact RFC 5652 section 11.4 preimage and nested for a countersignature of a countersignature; unsignedAttrs holds the decoded unsigned attributes with their type names. Both are unauthenticated by definition (an unsigned attribute is outside the signature) and never change signers[i].ok or res.valid; a present-but-invalid countersignature is surfaced ok:false, never silently dropped.
- pki.cms.sign gains an unsignedAttributes option: an array of { type, values } unsigned attributes placed in each SignerInfo, outside the signature. It is the vehicle for attaching an RFC 3161 timestamp token (id-aa-timeStampToken) or another unsigned attribute at signing time. content-type, message-digest, and signing-time are rejected as unsigned attributes (RFC 5652 sec. 11), as is a duplicate attribute type.

## v0.3.12 — 2026-07-23

pki.pkcs12.open reads and decrypts a password-integrity PKCS#12 store (RFC 7292, RFC 9579).

### Added

- pki.pkcs12.open(pfx, password, opts) reads a password-integrity PKCS#12 store. It verifies the classic Appendix B HMAC or RFC 9579 PBMAC1 MAC before decrypting (RFC 7292 sec. 5.1), then PBES2-decrypts every privacy safe and pkcs8ShroudedKeyBag, returning { integrityMode, macVerified, keys, certs, crls, secrets }, with private keys as re-validated PKCS#8 DER, certificates/CRLs/secrets as raw DER, all carrying friendlyName and localKeyId, and nested safeContents recursively. A wrong password fails at the MAC gate (pkcs12/mac-mismatch); a MAC-less store is refused (pkcs12/no-integrity) unless opts.allowUnauthenticated is set; a public-key-integrity store and a legacy (non-PBES2) bag are refused; a post-MAC decrypt failure is the uniform pkcs12/decrypt-failed. opts.maxIterations lowers the KDF/MAC iteration cap for the call, and opts.keys 'crypto' imports each private key to a WebCrypto CryptoKey (opts.importAlgorithm for the ambiguous RSA/EC arms). pfx accepts a DER Buffer, PEM string, or a pki.schema.pkcs12.parse result. RFC 7292 sec. 5.1, RFC 9579, RFC 8018.

## v0.3.11 — 2026-07-23

pki.pkcs12 builds and MAC-verifies password-integrity PKCS#12 (.p12/.pfx) stores (RFC 7292, RFC 9579).

### Added

- pki.pkcs12.build(spec, opts) builds a password-integrity PKCS#12 store. spec is { key, cert, ca?, friendlyName?, localKeyId? } (one PBES2-encrypted cert safe plus one shrouded-key safe) or { safeContents: [...] }, where each element is a plaintext or PBES2-encrypted SafeContents of key / shroudedKey / cert / crl / secret / nested safeContents bags; keys and certs are validated before wrapping. opts.mac selects a classic Appendix B HMAC (default) or an RFC 9579 PBMAC1 over SHA-256/384/512, or false for a MAC-less store; opts.password is the shared privacy + integrity password; opts.pem returns a PEM PKCS12 string. Shrouded keys and cert safes are encrypted under RFC 8018 PBES2 (AES-128/192/256-CBC). Passwords are BMPString+NULL encoded for the classic MAC and UTF-8 for the PBES2 bags and PBMAC1, so the output opens in OpenSSL and NSS; the MAC covers the exact AuthenticatedSafe byte range, a DEFAULT-1 MacData iterations and a <=160-bit PBMAC1 digest are rejected, and the store is re-parsed before return. RFC 7292, RFC 9579, RFC 8018.
- pki.pkcs12.verifyMac(pfx, password, opts) verifies a password-integrity store's MAC. pfx is a pki.schema.pkcs12.parse result, a DER Buffer, or a PEM string; the password is BMPString+NULL (classic) or UTF-8 (PBMAC1) encoded, the MAC is recomputed over the store's exact AuthenticatedSafe byte range with the store's own MAC parameters, and constant-time-compared to the stored value. Returns true / false for the password match; throws Pkcs12Error on a MAC-less or public-key-integrity store, or an unsupported MAC algorithm. RFC 7292 sec. 5.1, RFC 9579.
- pki.asn1.build.bmpString(str) encodes a JS string as a universal BMPString (UTF-16BE) TLV, rejecting an unpaired surrogate code point.

## v0.3.10 — 2026-07-23

pki.key exports, imports, and PBES2-encrypts private keys (RFC 5958, RFC 8018) over every WebCrypto algorithm.

### Added

- pki.key.encrypt(privateKey, password, opts) encrypts a PKCS#8 private key (DER, PEM, or an extractable CryptoKey) into an RFC 5958 EncryptedPrivateKeyInfo under RFC 8018 PBES2. opts selects the cipher (aes-256-cbc default, aes-192-cbc, aes-128-cbc), the pseudorandom function (hmacWithSHA256 default, SHA-384, SHA-512, SHA-1), the iteration count (default 600000, bounded by the decryptor's cap), and the salt (16 random octets by default); opts.pem returns an ENCRYPTED PRIVATE KEY string. The plaintext is validated as a well-formed PKCS#8 structure before encryption and the output is re-parsed before return. A default pseudorandom function is omitted and keyLength is omitted, so the parameters are byte-exact with OpenSSL. RFC 5958 sec. 3, RFC 8018.
- pki.key.decrypt(encrypted, password, opts) decrypts an RFC 5958 EncryptedPrivateKeyInfo (DER or ENCRYPTED PRIVATE KEY PEM), returning the inner PrivateKeyInfo re-validated through pki.schema.pkcs8.parse. Only PBES2 with a PBKDF2 key-derivation function and an AES-CBC scheme is accepted. PBES1, PBMAC1, scrypt, and any other algorithm are refused. The salt and iteration count are bounded before any key derivation (opts.maxIterations lowers the cap for this call, never raises it), a malformed parameter set or wrong-length IV is a distinct typed error, and, because a MAC-less PBES2-CBC decrypt must not be a padding oracle (RFC 8018 sec. 8), a wrong password and a valid pad that is not a private key both surface the single uniform decrypt-failed. RFC 5958 sec. 3, RFC 8018.
- pki.key.export(key, opts) exports an extractable CryptoKey to DER or PEM: a private key as PKCS#8, a public key as SubjectPublicKeyInfo. The encoding is delegated to WebCrypto, so the algorithm-specific parameters are correct: RSA an explicit NULL, EC a named curve, Ed25519/Ed448/X25519/X448 parameters absent (RFC 8410 sec. 3). RFC 5958, RFC 5280 sec. 4.1.2.7.
- pki.key.import(input, opts) imports a DER or PEM PKCS#8 private key, SPKI public key, or (with opts.password) an ENCRYPTED PRIVATE KEY into a CryptoKey, auto-detecting the structure. The WebCrypto algorithm is inferred for the algorithms that name exactly one (Ed25519, Ed448, X25519, X448, ML-DSA, ML-KEM, SLH-DSA); RSA and EC are ambiguous between signing and key agreement, so opts.algorithm is required for them; import fails closed and never guesses a use.
- pki.key.generate(algorithm, opts) generates a key pair over the WebCrypto engine (RSA, ECDSA/ECDH, Ed25519/Ed448, X25519/X448, and the FIPS post-quantum ML-DSA and ML-KEM), with usages defaulting to the algorithm's natural set. pki.key.publicFromPrivate(privateKey) derives the SubjectPublicKeyInfo public key from a private key.
- pki.errors.KeyError is the typed error for the pki.key domain (key/bad-input, key/unsupported-algorithm, key/bad-algorithm-parameters, key/iteration-limit, key/bad-version, key/decrypt-failed).

## v0.3.9 — 2026-07-23

pki.crl builds, signs, and verifies X.509 certificate revocation lists (RFC 5280 sec. 5) over any registry algorithm.

### Added

- pki.crl.sign(spec, issuer, opts) builds and signs an X.509 CRL (RFC 5280 sec. 5): thisUpdate/nextUpdate, an optional crlNumber, a revoked list (each entry a serialNumber and revocationDate with an optional reason or invalidityDate), and an extensions object (authorityKeyIdentifier, issuingDistributionPoint, deltaCRLIndicator, freshestCRL, authorityInfoAccess) or an array of pre-encoded Extension DER. The issuer is a CA certificate + key, or an explicit name + public key + key. The signature algorithm is resolved from the issuer key, so RSA (PKCS#1 v1.5 / PSS via opts.pss), ECDSA, EdDSA, ML-DSA, SLH-DSA, and the composite arms all sign without a per-algorithm branch. The version is derived from the extension set (v2 when any CRL or entry extension is present, else v1), an empty revocation list omits the field, the reason code is an ENUMERATED, an invalidity date is always a GeneralizedTime, and per-extension criticality is fixed by the profile. Returns DER or a PEM X509 CRL; the produced signature is verified under the issuer key before return, and every emitted CRL round-trips through pki.schema.crl.parse and is accepted by OpenSSL across the classical and post-quantum arms. RFC 5280 sec. 5.
- pki.crl.verify(crl, issuer) verifies a CRL's signature over its exact tbsCertList bytes against the issuer public key (a { cert }, a { publicKey } SPKI DER, or a raw SPKI Buffer), composing the one path-validation signature engine pki.path.crlChecker uses (RFC 9814 algorithm-confusion and Edwards low-order-point gates included) and failing closed to false. It checks the signature only; issuer authorization, currency, and distribution-point scope remain pki.path.crlChecker.
- pki.crl.isRevoked(crl, serialNumber) returns the revoked-certificate entry a CRL lists for a serial number, or null when the serial is not listed.

## v0.3.8 — 2026-07-18

Human-readable inspection extends to CRLs, CSRs, and CMS messages, with a pki.schema.detectFormat companion.

### Added

- pki.inspect.crl / .csr / .cms render a certificate revocation list, a PKCS#10 certification request, and a CMS message as OpenSSL-familiar text reports (openssl crl -text / req -text / cms -cmsout -print), and pki.inspect.any detects the format of a DER/PEM input and routes it to the matching report. Each composes the certificate inspector's shipped field renderers, resolves every extension/attribute/algorithm/content-type OID through the registry (unknown -> dotted, undecodable value -> raw octets), and is best-effort: a malformed part hex-dumps without failing the report, and only entry-point coercion throws (inspect/bad-crl / inspect/bad-csr / inspect/bad-cms / inspect/unsupported-format). Cross-checked field-for-field against OpenSSL. RFC 5280 / RFC 2986 / RFC 5652.
- pki.schema.detectFormat(input) returns the registered PKI format name a DER Buffer or PEM string encodes (one of pki.schema.all()) without parsing it, or null when it matches no registered format. It is the detection half of pki.schema.parse, over the same authoritative format ordering.

## v0.3.7 — 2026-07-17

Certification path building arrives as pki.path.build, and pki.lint gains seven RFC 5280 extension-criticality and CA-scope lints.

### Added

- pki.path.build(leaf, opts) is the discovering complement of pki.path.validate: it finds the ordered certification path from a leaf up to a trust anchor over an untrusted pool of candidate CA certificates, then validates it. Candidates are matched by RFC 5280 name chaining, prioritized by the RFC 4158 heuristics (subjectKeyIdentifier/authorityKeyIdentifier match, anchor-adjacent issuer, CA and keyCertSign, validity), and searched depth-first with backtracking; every accept flows through pki.path.validate, so a name or key-identifier match is only an ordering hint and building never weakens a path-validation check. The search is bounded (a chain-length cap, a total-work cap on candidate expansions, and an identity-tuple visited-set) so a cross-certificate cycle or Bridge-CA fan-out terminates deterministically; the trust store accepts anchor tuples or self-signed root certificates, opts.validate:false returns the ordered path unvalidated, and the verdict is cross-checked against openssl verify. AIA caIssuers fetching is offline-only (supply fetched issuers in opts.candidates). RFC 4158 / RFC 5280.
- pki.lint.certificate flags seven RFC 5280 extension-criticality and CA-scope violations that parse but breach the certificate profile: basicConstraints (on a certificate-signing CA), nameConstraints, policyConstraints, and inhibitAnyPolicy must be marked critical (error); keyUsage should be critical (warn); nameConstraints must appear only in a CA certificate (error); and an end-entity certificate should carry a subjectKeyIdentifier (notice). The basicConstraints criticality rule applies only when the CA key validates certificate signatures (RFC 5280 4.2.1.9), so a CRL-signing-only CA carrying a non-critical basicConstraints is not falsely flagged.

## v0.3.6 — 2026-07-17

pki.cmp.build gains the CA/responder side. Certificate, revocation, key-recovery, general, error, poll, and confirmation responses complete the RFC 9810 message surface.

### Added

- pki.cmp.build message.body now accepts the CA/responder-side arms: ip / cp / kup / ccp (a CertRepMessage, holding caPubs plus a response of CertResponse entries, each carrying a PKIStatusInfo and, under a granting status, a certifiedKeyPair), rp (a RevRepContent), krp (a KeyRecRepContent), genp (a general response), error (an ErrorMsgContent), pollRep (a poll response), and pkiconf (the final confirmation). They reuse the request-side header, envelope, ProtectedPart, and signature / PBMAC1 protection, and round-trip through pki.schema.cmp.parse. The RFC 9810 section 5.3.4 rules are enforced (a certifiedKeyPair only under a granting status and never with a failInfo, a validated certificate CHOICE, a single-response ccp). The private-key-transport / KEM encrypted forms ride a pre-encoded escape hatch.

## v0.3.5 — 2026-07-17

pki.cmp.build assembles protected RFC 9810 CMP PKIMessages: certificate requests, confirmations, revocations, and general messages, protected by a sender-key signature or a PBMAC1 shared secret.

### Added

- pki.cmp.build(message, opts) assembles a protected RFC 9810 CMP PKIMessage. message.header carries the sender / recipient GeneralNames (including the anonymous NULL-DN) and optional transaction metadata; message.body is a single-key arm: ir / cr / kur (a CertReqMessages via pki.crmf.build), p10cr (a PKCS#10 CertificationRequest), certConf, pollReq, genm, or rr. Protection is exactly one of opts.{ key, cert } (a signature under the sender key, algorithm resolved from the certificate: RSA / ECDSA / EdDSA / ML-DSA / SLH-DSA / composite) or opts.mac (a PBMAC1 shared-secret HMAC, RFC 9481 / RFC 9579), computed over the exact ProtectedPart DER and self-verified before return. Returns DER, or a PEM CMP block with opts.pem; malformed input throws a typed CmpError. Message parsing remains pki.schema.cmp.parse.
- pki.crmf.buildCertTemplate(template) encodes a bare RFC 4211 CertTemplate (subject, public key, validity, requested extensions, version) to canonical DER. This is the certTemplate interior of pki.crmf.build, exposed for the CMP rr revocation body whose certDetails names the certificate to revoke.

## v0.3.4 — 2026-07-17

pki.schema.c509.encode produces C509 CBOR certificates. A DER X.509 certificate compresses to a compact, byte-exact-invertible type-3 C509, and a deterministic-CBOR encoder joins pki.cbor.

### Added

- pki.schema.c509.encode(input) encodes a C509 certificate to deterministic-CBOR bytes: a DER X.509 v3 certificate to a compact type-3 C509 (byte-exact-invertible, so the original signature verifies), or a pki.schema.c509.parse result re-emitted to its native array. Canonical deterministic CBOR with the registry integer shorthands and the C509 compressions; a certificate outside the invertible covered set throws a typed C509Error. Certificate parsing remains pki.schema.c509.parse.
- pki.cbor.build is a deterministic-CBOR encoder (RFC 8949 section 4.2), the byte-exact inverse of pki.cbor.decode: shortest-form heads, definite lengths, sorted and unique map keys, over unsigned and negative integers, byte and text strings, arrays, maps, tags, and the tagged bignum / epoch-time / object-identifier leaves. Encoded output always re-decodes through the strict decoder.

## v0.3.3 — 2026-07-17

pki.crmf.build issues RFC 4211 certificate request messages: a CertReqMessages with a signature proof of possession, over every algorithm the toolkit supports.

### Added

- pki.crmf.build(spec, key, opts) builds and DER-encodes an RFC 4211 CertReqMessages and returns DER, or a PEM block with opts.pem. The message carries a CertTemplate of the requested certificate fields plus a POPOSigningKey proof of possession signed with the requester's key, or a raVerified proof, opted into without a key. The signing algorithm is resolved from the requested public key: RSA PKCS#1 v1.5 / PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm. Requested v3 extensions, registration controls, and regInfo ride in the message; pass an array of specs for a batch. Certificate-request-message parsing remains pki.schema.crmf.parse.
- pki.asn1.build.implicit(tag, tlv) retags an encoded universal TLV as a context-class IMPLICIT [tag], preserving the source's primitive/constructed bit and content, so the CertTemplate and other context-tagged structures all compose one home for IMPLICIT tag replacement.

## v0.3.2 — 2026-07-17

pki.attrcert.sign issues RFC 5755 attribute certificates: an Attribute Authority binds a holder to privilege attributes and signs with any algorithm the toolkit supports.

### Added

- pki.attrcert.sign(spec, issuer, opts) builds and signs an RFC 5755 attribute certificate as an Attribute Authority, and returns DER, or a PEM ATTRIBUTE CERTIFICATE with opts.pem. The holder is exactly one of an entity name, a baseCertificateID, a fromCertificate binding derived from a public-key certificate, or an object digest; the attributes are the sec. 4.4 privilege syntaxes (role, clearance, group, chargingIdentity, accessIdentity, authenticationInfo) or pre-encoded Attribute DER; the extensions are auditIdentity, targetInformation, noRevAvail, aaControls, acProxying, and authorityKeyIdentifier or pre-encoded Extension DER, each carried with its RFC 5755 criticality. The AA signs with RSA PKCS#1 v1.5 / PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm, and the signature is verified under the AA public key before the certificate is returned. Attribute-certificate parsing remains pki.schema.attrcert.parse.

## v0.3.1 — 2026-07-17

pki.csr.sign issues PKCS#10 certification requests, self-signed by the subject key for proof of possession, over every signature algorithm the toolkit supports.

### Added

- pki.csr.sign(spec, key, opts) builds a PKCS#10 certification request and self-signs it with the subject's own key as proof of possession, returning DER, or a PEM CERTIFICATE REQUEST with opts.pem. The subject may be empty; requested v3 extensions (subject alternative names, key usage, extended key usage, basic constraints, certificate policies, subject key identifier, or pre-encoded Extension DER) ride in a PKCS#9 extensionRequest attribute a CA copies into the issued certificate, and an optional challengePassword is carried too. The signing algorithm is resolved from the subject key: RSA PKCS#1 v1.5 / PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA, or a composite arm. Request parsing remains pki.schema.csr.parse.

### Fixed

- The certificate and certification-request distinguished-name and extension encoders now reject an unrecognized attribute, extended-key-usage purpose, or certificate-policy name at build time with a typed error, so no malformed object identifier is emitted. An unknown name in a pki.x509.sign or pki.csr.sign spec fails closed and produces no unparseable structure.

## v0.3.0 — 2026-07-16

pki.x509.sign issues self-signed and CA-signed X.509 certificates over every signature algorithm the toolkit supports, from RSA and ECDSA through EdDSA, ML-DSA, and SLH-DSA.

### Added

- pki.x509.sign(spec, issuer, opts) builds and signs an X.509 certificate and returns DER, or a PEM CERTIFICATE string with opts.pem. Pass a signing key alone for a self-signed certificate; pass an explicit issuer name and public key, or an issuing certificate, for a CA-signed one. The signing algorithm is resolved from the key: RSA PKCS#1 v1.5, RSASSA-PSS (opts.pss), ECDSA P-256/P-384/P-521, Ed25519, Ed448, ML-DSA-44/65/87, the twelve SLH-DSA parameter sets, and the composite arms. The version, serial-number bounds, UTCTime/GeneralizedTime cutover, DER default omissions, and the CA cross-field rules are enforced; malformed input throws a typed CertificateError. Certificate parsing remains pki.schema.x509.parse.
- pki.asn1.build.namedBitString(positions) encodes a minimal DER NamedBitList (X.690 section 11.2.2): the asserted bit positions with every trailing zero bit removed. The keyUsage and PKIFailureInfo encoders now compose it as their single canonical encoder.

### Security

- The Sigstore bundle verifier now routes an Ed25519 or Ed448 key through the shared full-order, on-curve Edwards-point gate at the raw signature-verification sink as well as at key parsing. A low-order or off-curve key that would verify a forged EdDSA signature is refused wherever a verify path handles one. This completes the defense across every EdDSA verification sink in the toolkit.

## v0.2.33 — 2026-07-16

Attribute certificates now decode their RFC 5755 attribute values and attribute-certificate extensions alongside the certificate structure.

### Added

- pki.schema.attrcert.parse decodes the RFC 5755 section 4.4 attribute values: role (RoleSyntax), clearance (Clearance, including the classification bit list and security categories), authenticationInfo and accessIdentity (SvceAuthInfo), and group and chargingIdentity (IetfAttrSyntax). It also decodes the section 4.3 attribute-certificate extensions: auditIdentity, targetInformation and proxyInfo (Targets, with targetCert reusing the IssuerSerial decoder), noRevAvail, and aaControls. Each is surfaced additively (a decoded field alongside the raw value) through the parse consumer path; an unrecognized attribute type or extension id is preserved opaque, and a malformed recognized value fails closed with a typed error. Every GeneralName inside these structures is validated through the shared name decoder.

## v0.2.32 — 2026-07-16

X.509 certificates now decode the Microsoft Active Directory Certificate Services enrollment extensions, and pki.lint's critical-extension check is aligned with certification-path validation.

### Added

- pki.schema.x509.parse decodes the Microsoft Active Directory Certificate Services enrollment extensions ([MS-WCCE] / [MS-CRTD]): the v2 certificate template (szOID-CERTIFICATE_TEMPLATE: template OID plus major/minor version), the legacy v1 template name (szOID-ENROLL_CERTTYPE_EXTENSION), the CA version (szOID-CERTSRV_CA_VERSION, surfaced as the raw value and as the CA key index / certificate index split), the previous-CA-certificate hash (szOID-CERTSRV_PREVIOUS_CERT_HASH), and the application policies (szOID-APPLICATION_CERT_POLICIES, decoded as RFC 5280 certificate policies). Each is rendered by pki.inspect and fails closed with a typed error on a malformed shape. The version fields accept the full 32-bit range Active Directory uses; a signed subset would be too narrow.

### Changed

- pki.lint's unrecognized-critical-extension check now mirrors certification-path validation: it reports a critical extension whose semantics the path validator does not process (an authority/subject key identifier, a freshest-CRL pointer, an SCT list, a qualified-certificate statement, or a Microsoft enterprise-CA extension). An extension it can merely decode no longer counts as processed. precertificatePoison, which RFC 6962 requires to be critical, is not reported. A conforming relying party must reject a critical extension it cannot process, so a certificate whose critical enterprise or qualified-certificate constraints this toolkit does not enforce is now surfaced by the linter.

## v0.2.31 — 2026-07-16

X.509 certificates now decode the RFC 3739 / ETSI EN 319 412-5 qualified-certificate qcStatements extension, and the sigstore verifier gains a low-order EdDSA public-key gate.

### Added

- The toolkit decodes the RFC 3739 sec. 3.2.6 / ETSI EN 319 412-5 qualified-certificate qcStatements extension (id-pe-qcStatements). The decoded statements are validated by the toolkit's certificate-extension decoders and rendered by pki.inspect: QcCompliance (EU-qualified), QcLimitValue (reliance limit), QcSSCD (key in a QSCD), QcType (certificate purpose: esign / eseal / web), QcRetentionPeriod, QcPDS (disclosure-statement URLs), QcCClegislation (country of qualification), QcIdentMethod, QcQSCDlegislation, and the PKIX SemanticsInformation. An unknown statementId is preserved opaque (its raw bytes, semantics not executed); a malformed shape fails closed with a typed error.

### Security

- The sigstore keyless-bundle verifier now routes an Ed25519/Ed448 Fulcio leaf or Rekor log public key through the shared full-order Edwards-point gate before verification. A low-order OKP key (which node imports without complaint and which can verify a forged EdDSA signature) is rejected at key-parse (sigstore/bad-key) instead of being handed to verify, the same defense the webauthn and certification-path EdDSA verifiers already apply.
- Certification-path validation rejects a critical qcStatements extension (RFC 5280 sec. 6.1.4). A critical qualified-certificate statement asserts semantics a relying party must enforce (a QcLimitValue reliance limit, a QcType certificate purpose), and the validator does not enforce them, so treating the extension as processed would let a caller rely on a certificate outside its asserted qualified-certificate constraints; it is left unprocessed and fails as an unrecognized critical extension. A non-critical qcStatements is informational and does not affect the verdict; the extension is still decoded for pki.inspect and lint, and the linter flags a critical qcStatements as an unrecognized critical extension for the same reason: structural decodability is not validation processing.

## v0.2.30 — 2026-07-16

C509 CBOR-encoded certificates arrive as pki.schema.c509.parse: decode the compact CBOR profile of X.509 in both its natively-signed and X.509-re-encoded forms, reconstructing the original DER byte-for-byte so the original signature still verifies.

### Added

- pki.schema.c509.parse(bytes) decodes a C509 CBOR-encoded certificate (draft-ietf-cose-cbor-encoded-cert) into structured, validated fields. It reads both certificate forms, natively-signed (c509CertificateType 2) and the CBOR re-encoding of a DER X.509 v3 certificate (type 3), over the strict deterministic-CBOR codec, fail-closed. For a type-3 certificate it reconstructs the original DER byte-for-byte (de-compressing the EC point, re-emitting each field as canonical DER, re-wrapping the ECDSA signature) so the original signature verifies and the certificate round-trips through pki.schema.x509.parse; a field it cannot invert byte-exactly fails closed. It decodes CBOR instead of DER, so it is an explicit-call surface and is not auto-routed by pki.schema.parse.

### Fixed

- Certification-path validation now rejects a trust anchor whose per-purpose distrust-after date is an invalid Date at input (path/bad-input). Previously a malformed date value passed the Date type check but compared as not-a-number, silently disabling the distrust-after restriction it was meant to enforce.

## v0.2.29 — 2026-07-16

Certificate Transparency log-list signature verification arrives as pki.ct.verifyLogListSignature: verify the detached signature published alongside the CT log list against a caller-pinned signer key, completing the offline log-list trust chain.

### Added

- pki.ct.verifyLogListSignature(json, signature, publicKey) verifies the detached signature over the Certificate Transparency log list (log_list.sig over log_list.json). The message is the raw json bytes, verified byte-for-byte with no canonicalization; publicKey is the caller-pinned signer SubjectPublicKeyInfo (there is no embedded key). The scheme is RSASSA-PKCS1-v1.5 with SHA-256 (an EC P-256 arm is accepted for future-proofing). It resolves true or false (a cryptographic verdict) and throws a typed CtError on a forgeable or unsupported key (an RSA exponent below 3, a sub-2048-bit RSA key, an unsupported key type or curve, a non-conformant ECDSA DER signature). Its verdict is cross-checked against OpenSSL's dgst -verify. Paired with pki.ct.parseLogList, this completes the offline CT log-list trust chain.

## v0.2.28 — 2026-07-16

The Certificate Transparency log-list trust surface arrives as pki.ct.parseLogList and pki.ct.verifySctWithLogList: resolve a trusted CT log's key from an SCT's log id and verify it in one step, ingesting the CT log-list JSON into state- and temporal-interval-constrained trusted logs.

### Added

- pki.ct.parseLogList(json, opts) ingests a Certificate Transparency log-list JSON document into { logs, byLogId }, constraint-carrying trusted logs keyed by log id. Each log's key is base64-decoded to its DER SubjectPublicKeyInfo and validated as on-profile; the log id is recomputed as SHA-256 of the key and must equal the stated log_id (RFC 6962 section 3.2, ct/log-id-mismatch), so a swapped key or a flipped id is refused. The state (exactly one of pending/qualified/usable/readonly/retired/rejected) and temporal_interval decode into trust constraints, and two entries for one recomputed id must agree or the list is rejected (ct/duplicate-log). Parsing is offline and routes through the bounded, duplicate-member-rejecting JSON reader; every malformed input is a typed CtError.
- pki.ct.verifySctWithLogList(entry, sct, logList, opts) resolves the trusted CT log for an SCT by its log id and verifies it in one step. The log's state gates trust (usable/qualified/readonly proceed; a retired log only for an SCT timestamped before its retirement; pending/rejected are ct/log-untrusted) and its temporal_interval gates the covered certificate (the cert's notAfter, from the leaf certificate for a precert-free entry or opts.certNotAfter, must fall in the log's window, and a windowed log with no resolvable notAfter is ct/temporal-interval, never silently skipped). The signature check is delegated to the shipped pki.ct.verifySct. Resolves true for a valid signature from a trusted, in-window log, false on a cryptographic mismatch, and throws a typed CtError on any structural or trust failure.

## v0.2.27 — 2026-07-16

CMS CompressedData arrives as pki.cms.compress / pki.cms.decompress, with the matching S/MIME pki.smime.compress / pki.smime.decompress: compress and recover RFC 3274 messages, with a bounded inflate that defends the decompression-bomb class.

### Added

- pki.cms.compress(content, opts) and pki.cms.decompress(input, opts) produce and consume a CMS CompressedData (RFC 3274): ZLIB (RFC 1950 / RFC 1951) compression, version 0, id-alg-zlibCompress with omitted parameters. opts.contentType sets the inner content type (default id-data), opts.level the DEFLATE level, opts.pem returns PEM. Decompress requires version 0, id-alg-zlibCompress with absent-or-NULL parameters, and a present encapsulated content; it bounds the decompressed output at C.LIMITS.COMPRESS_MAX_BYTES (16 MiB, tightened downward via opts.maxOutputBytes) and stops before the output is materialized, so a decompression bomb throws cms/decompress-too-large before memory is exhausted. Every malformed or truncated stream fails closed as cms/decompress-failed. Fail-closed with typed CmsError.
- pki.smime.compress(content, opts) and pki.smime.decompress(message, opts) assemble and open a compressed S/MIME message (RFC 8551 section 3.6): an opaque application/pkcs7-mime; smime-type=compressed-data; name=smime.p7z entity whose base64 body is a CMS CompressedData. The MIME entity is canonicalized before compression and recovered exactly; the recovered content (which may itself be a signed or enveloped S/MIME message) is returned for the caller to feed back to pki.smime.verify / pki.smime.decrypt. Compression is a size transform with no integrity, confidentiality, or authentication (RFC 8551 section 2.4.5). Receive-tolerant: OpenSSL's legacy application/x-pkcs7-mime and a missing smime-type are both accepted.

## v0.2.26 — 2026-07-16

S/MIME encryption arrives as pki.smime.encrypt / pki.smime.decrypt: envelope and open RFC 8551 encrypted messages over the CMS layer, with AES-GCM authenticated enveloping as the default and bidirectional OpenSSL interoperability.

### Added

- pki.smime.encrypt(content, recipients, opts) envelopes a MIME entity as an encrypted RFC 8551 S/MIME message (opaque application/pkcs7-mime). The default AES-256-GCM content encryption yields an authEnveloped-data message (confidentiality and integrity, RFC 8551 sec. 3.4); opts.contentEncryptionAlgorithm can select AES-CBC for an enveloped-data message (confidentiality only, RFC 8551 sec. 3.3). recipients is the pki.cms.encrypt recipient array (RSA-OAEP key transport, ECDH / X25519 / X448 key agreement, AES key wrap, PBKDF2 password, and post-quantum ML-KEM), and a single descriptor is accepted and normalized to a one-element array. content is wrapped as a text/plain entity by default or taken verbatim with opts.entity. Fail-closed with typed SmimeError.
- pki.smime.decrypt(message, keyMaterial, opts) opens an encrypted S/MIME message, returning the recovered inner MIME entity plus smimeType, authenticated (true only for an AuthEnvelopedData; a CBC enveloped-data message reports false, the RFC 8551 sec. 3.3 no-integrity caveat), recipientType, recipientIndex, and contentEncryptionAlgorithm. The smime-type is derived from the CMS body and never from the header; opts.strictSmimeType additionally rejects a header smime-type that disagrees with the body. keyMaterial is the pki.cms.decrypt key material ({ key, cert }, { password }, or { kek, kekId }). Decryption is fail-closed and oracle-free. OpenSSL's legacy application/x-pkcs7-mime and a missing smime-type are both accepted. A recovered content that is itself a signed S/MIME message is returned for the caller to feed back to pki.smime.verify. Bidirectionally interoperable with openssl cms -encrypt / -decrypt.

## v0.2.25 — 2026-07-16

S/MIME signed-message assembly and verification arrive as pki.smime: sign and verify RFC 8551 multipart/signed and application/pkcs7-mime messages over the CMS layer, bidirectionally interoperable with OpenSSL.

### Added

- pki.smime.sign(content, signers, opts) assembles a signed RFC 8551 S/MIME message. opts.form selects multipart/signed (default, clear-signed: the canonical entity in the first part and a detached CMS SignedData over its canonical form as an application/pkcs7-signature second part, with protocol="application/pkcs7-signature" and a matching micalg) or pkcs7-mime (opaque: one application/pkcs7-mime; smime-type=signed-data entity whose base64 body is an attached CMS SignedData). content is wrapped as a text/plain entity by default or taken verbatim with opts.entity. Any pki.cms.sign signer (RSA / RSASSA-PSS / ECDSA / EdDSA / ML-DSA / SLH-DSA) carries through. Fail-closed with typed SmimeError.
- pki.smime.verify(message, opts) unwraps and verifies a signed S/MIME message in both forms, recomputing the detached signature over the first part's RFC 8551 sec. 3.1.1 canonical form (the same canonicalizer the signer used, so a line-ending-mangling transport still verifies and a tampered part fails). It returns pki.cms.verify's { valid, signers } verdict plus the form, the recovered content, and the micalg; a micalg disagreeing with the actual digest is advisory unless opts.strictMicalg. Chaining a signer to a trust anchor is the caller's pki.path.validate step. Bidirectionally interoperable with openssl smime and openssl cms.

## v0.2.24 — 2026-07-16

SCT-list encoding and log signing join pki.ct: encodeSctList builds an RFC 6962 SignedCertificateTimestampList byte-for-byte, and signSct performs a Certificate Transparency log's signing step, completing the parse/verify/encode/sign symmetry.

### Added

- pki.ct.encodeSctList(scts) builds an RFC 6962 SCT-list extension value from an array of SCTs, the exact inverse of pki.ct.parseSctList (byte-identical round-trip). A decoded v1 SCT is rebuilt from its fields in the RFC 6962 sec. 3.2 order; an opaque non-v1 entry re-emits its rawSct verbatim (forward compatibility). The list must be non-empty and stays within the parser's SCT_MAX_COUNT / SCT_MAX_BYTES caps. Fail-closed with a typed CtError.
- pki.ct.signSct(entry, logKey, opts) performs a Certificate Transparency log's signing step (RFC 6962 sec. 3.2): it rebuilds the digitally-signed preimage via the same reconstructSignedData builder the verifier hashes, signs it with the log's private key (ECDSA NIST P-256 or RSA >= 2048, SHA-256 per sec. 2.1.4), and returns a fully-formed v1 SCT that pki.ct.verifySct accepts. The LogID is derived as SHA-256 of the log's SubjectPublicKeyInfo (sec. 3.4); a supplied opts.logId must match. Composes with encodeSctList to assemble a signed SCT-list extension.

## v0.2.23 — 2026-07-16

CMS content encryption arrives as pki.cms.encrypt and pki.cms.decrypt: EnvelopedData, AuthEnvelopedData, and EncryptedData with every RFC 5652 recipient type (RSA-OAEP, ephemeral-static ECDH, X25519/X448, symmetric key-wrap, password, and post-quantum ML-KEM per RFC 9629/9936), and a single, oracle-free decryption verdict.

### Added

- pki.cms.encrypt(content, recipients, opts) produces a CMS EnvelopedData, AuthEnvelopedData (AES-GCM, the default), or EncryptedData. Recipients auto-dispatch off the certificate key: RSA -> ktri RSAES-OAEP-SHA256/384/512 (v1.5 never emitted); EC P-256/384/521 -> kari ephemeral-static ECDH with the ANSI-X9.63 KDF; X25519/X448 -> kari with HKDF (RFC 8418); ML-KEM-512/768/1024 -> ori/KEMRecipientInfo (RFC 9629/9936). A { password } recipient uses PBKDF2 + the RFC 3211 PWRI-KEK; a { kek, kekId } recipient uses AES key wrap. EncryptedData takes a raw { cek } or a PBES2 { password }. Content is AES-128/192/256-GCM or -CBC; the same fresh content-encryption key is wrapped for every recipient. Fail-closed with typed CmsError.
- pki.cms.decrypt(input, keyMaterial, opts) decrypts an EnvelopedData / AuthEnvelopedData / EncryptedData (DER or PEM). It selects the recipient the key material { key, cert } / { password } / { kek } / { cek } targets, acquires the content-encryption key through the matching arm (RSA-OAEP or PKCS#1 v1.5 decrypt-only under the RFC 3218 implicit-rejection countermeasure, ECDH / X25519 / X448, AES key-unwrap, PBKDF2, ML-KEM decapsulation), and decrypts + authenticates the content, returning { content, contentType, contentTypeName, recipientType, recipientIndex, contentEncryptionAlgorithm, authenticated }. Every secret-dependent failure collapses to one uniform cms/decrypt-failed verdict (Bleichenbacher / EFAIL / password-oracle freedom); a PBKDF2 iteration cap bounds password-based decryption work.
- The WebCrypto engine gains ML-KEM key encapsulation (SubtleCrypto.encapsulateBits / decapsulateBits over FIPS 203) and the ANSI-X9.63 single-step key-derivation function (the X963KDF derive algorithm), the two primitives the post-quantum and elliptic-curve CMS recipient arms compose.

## v0.2.22 — 2026-07-15

The RFC 6960 OCSP producer and relying-party surface arrives as pki.ocsp: build and sign OCSP requests and responses, mint unsigned error responses, and verify a response end to end against the same hardened responder-authorization, signature, CertID, currency, and nonce gates the certification-path revocation checker runs.

### Added

- pki.ocsp is the RFC 6960 OCSP request/response surface. pki.ocsp.buildRequest(query, opts) builds an OCSPRequest (one or many { cert, issuer } queries; CertID under SHA-1 or SHA-2; optional RFC 9654 nonce; optional requestor signature; the RFC 5019 lightweight profile). pki.ocsp.sign(responseData, responder, opts) signs a BasicOCSPResponse over the exact ResponseData DER for the issuing CA or a delegated responder, with good / revoked / unknown per-certificate status and any pki.cms.sign signature algorithm (RSA, RSASSA-PSS, ECDSA, EdDSA, the post-quantum ML-DSA and SLH-DSA sets). pki.ocsp.buildErrorResponse(status) mints the unsigned section 2.3 error response. Transport-free; malformed input throws a typed OcspError.
- pki.ocsp.verify(response, opts) verifies an OCSP response as a relying party, fail-closed: it binds the supplied issuer certificate to the target certificate (the target's issuer name must equal the issuer's subject and the target's signature must verify under the issuer's key), recomputes the CertID under its own hash algorithm to bind the checked certificate to its issuer, requires an authorized responder (the issuing CA, or a CA-issued delegate bearing id-kp-OCSPSigning and id-pkix-ocsp-nocheck that passes the full out-of-path certificate gates), verifies the signature over tbsResponseDataBytes, enforces thisUpdate / nextUpdate currency, and binds the request nonce (RFC 9654) under a constant-time comparison. A revoked status shadows good within a response; an unbound issuer, an unauthorized responder, a mismatched CertID, or a stale or unverifiable response returns { status: "unknown" } with granular responderAuthorized / signatureValid / matched flags, never a silent accept. It runs the exact responder-authorization, signature, and currency gates pki.path.ocspChecker runs, through one shared core.
- pki.path.verifyOcspResponse(parsedResponse, cert, issuerCert, time, opts) is the lower-level primitive pki.ocsp.verify composes: it verifies a single already-parsed OCSP response for one certificate against its already-parsed issuer, returning the same fail-closed granular verdict, for callers that have already decoded their inputs.

## v0.2.21 — 2026-07-15

ML-KEM public keys in X.509 certificates and PKCS#8 private keys (RFC 9935 / FIPS 203) become a first-class, fail-closed surface: certification-path validation enforces the keyEncipherment-only key usage, key import validates the private-key CHOICE and rejects an inconsistent key with a typed error, and pki.lint gains the RFC 9935 certificate rows.

### Added

- pki.path.validate enforces the RFC 9935 section 5 key-usage rule for ML-KEM (id-ml-kem-512/768/1024) certificates: a present keyUsage MUST assert keyEncipherment as the only bit. A leaf with digitalSignature, an ML-KEM key with keyCertSign / cRLSign / keyAgreement / dataEncipherment / nonRepudiation, or keyEncipherment set alongside any reserved bit, fails closed with the frozen code path/kem-key-usage, for the target and every intermediate whose own subject key is ML-KEM. An absent keyUsage places no restriction (RFC 5280 section 4.2.1.3).
- pki.lint gains an rfc9935 profile: lint/rfc9935/kem-key-usage (the section 5 keyEncipherment-only rule) and lint/rfc9935/kem-key-length (the SPKI encapsulation key must be exactly 800 / 1184 / 1568 octets for the id-ml-kem-512 / 768 / 1024 OID; the OID is the sole authority for the parameter set, so an OCTET-STRING-wrapped or wrong-set key is flagged). Both run by default and are silent on a non-ML-KEM certificate.

### Fixed

- pki.webcrypto.subtle.importKey no longer surfaces a raw engine exception when handed a malformed or inconsistent key: a bad SPKI, a bad JWK, or an ML-KEM private key whose seed and expanded halves are inconsistent (FIPS 203 section 7.3) now fails closed with a typed webcrypto/data error. For an ML-KEM PKCS#8, the RFC 9935 section 6 private-key CHOICE is validated by its DER tag and exact size for the algorithm OID before the engine imports it. The OpenSSL-legacy bare-seed, bare-expanded-key, and concatenated layouts the engine would otherwise accept are rejected, so a non-conformant private key cannot be imported under an ML-KEM name.
- pki.webcrypto.subtle.importKey now fails closed on two further malformed-input classes: a JWK import whose key data is not an object (null, a primitive, or an array, including the JSON null an unwrap over non-authenticating ciphertext can yield) returns a typed webcrypto/data error instead of a raw TypeError; and an SPKI or PKCS#8 import requested under a secret-key or key-derivation algorithm name (AES-GCM/CBC/CTR/KW, HMAC, HKDF, PBKDF2) is rejected as webcrypto/not-supported, and no mislabeled key handle is imported.

## v0.2.20 — 2026-07-15

A WebAuthn attestation object whose attestation statement is not a CBOR map is now rejected with a typed webauthn/bad-attestation-object at parse instead of surfacing an untyped error from a format verifier, and the strict CBOR codec gains pki.cbor.read.mapGet: a keyed map lookup that asserts the map's major type inside the accessor.

### Added

- pki.cbor.read.mapGet(node, key) -- the keyed lookup over a decoded CBOR map (RFC 8949 major type 5). A text-string key matches text-string map keys; an integer key (a safe-integer number or a BigInt, as COSE labels are) matches integer map keys; matching never coerces across the two. It returns the value node, or null when the map has no such entry. Decode already enforced key uniqueness, so at most one entry can match. A non-map node throws cbor/unexpected-major, and a key that is neither a text string nor an integer throws a TypeError.

### Changed

- A WebAuthn attestation object whose attStmt is not a CBOR map is now classified as a malformed attestation object (webauthn/bad-attestation-object, thrown at parse for every attestation format), where it previously surfaced as a per-format webauthn/bad-att-stmt or an untyped error depending on the CBOR type carried.

### Fixed

- pki.webauthn.parseAttestationObject and pki.webauthn.verify no longer throw a raw TypeError when the attestation object's attStmt is a CBOR array: the attestation-statement field walk read the array's children as key/value pairs and dereferenced undefined. The attestation object's attStmt shape is now validated at parse (WebAuthn sec. 6.5.4), and the statement walk reads its pairs through pki.cbor.read.map, which asserts the major type: malformed hostile bytes are a typed webauthn/* verdict, never an untyped crash.

## v0.2.19 — 2026-07-14

The RFC 3161 Time-Stamp Protocol surface is complete: pki.tsp.request and pki.tsp.response build and parse the protocol's request and response messages, and pki.tsp.verify verifies a timestamp token end to end: the CMS signature, the message imprint, the ESSCertID(V2) certificate binding, the critical timeStamping-only extendedKeyUsage, and full validation of the TSA certificate at the token's own genTime.

### Added

- pki.tsp.request builds an RFC 3161 TimeStampReq around a message imprint, with the optional nonce, requested TSA policy, certReq, and extensions (canonical DER, the DEFAULT-FALSE certReq omitted unless true), and pki.tsp.parseRequest parses one (a new TimeStampReq decoder, also exposed as pki.schema.tsp.parseRequest). pki.tsp.response builds a TimeStampResp: a granted status wrapping the token pki.tsp.sign produces, or a rejection carrying a PKIStatus, status text, and PKIFailureInfo names. pki.tsp.parseResponse parses one, and the section 2.4.2 status-to-token coupling (a granted response carries a token, any other status must not) is enforced on build and parse alike. These are the byte payloads an RFC 3161 transport carries, completing the protocol message surface around pki.tsp.sign and pki.schema.tsp.parseToken.
- pki.tsp.verify(token, data, opts) verifies a timestamp token and returns a verdict carrying the verified genTime, serial number, and TSTInfo fields. It checks the CMS signature over the exact signed bytes, recomputes the message imprint from the supplied data (or compares a precomputed imprint), requires the encapsulated content be a TSTInfo, binds the token to the TSA certificate by recomputing the ESSCertID(V2) certificate hash (RFC 5816) and matching its issuerSerial when present, and enforces RFC 3161 section 2.3 on the TSA certificate: its extendedKeyUsage must be present, critical, and contain exactly id-kp-timeStamping, and, when the certificate asserts a keyUsage, that keyUsage must permit signing, so a certificate not issued for timestamping cannot mint a trusted token. When a trust anchor is supplied, the TSA certificate chain (ordered from the token's embedded certificates, so a TSA under an intermediate CA validates) receives full certification-path validation at the token's genTime, including optional revocation; when the request carried a nonce, the token must echo it. Every checked field is read from the verified encapsulated content, never a caller-supplied parsed object; a well-formed token failing any check is a fail-closed { valid: false } verdict with a stable reason code.

### Fixed

- CMS signer-certificate lookup now matches the certificate's issuer name in addition to its serial number when a signer is identified by issuerAndSerialNumber (RFC 5652); the issuer comparison was previously inert, so a signer was located by serial number alone. The verification verdict is unchanged (the signature check remains the authority), but the correct signer certificate is now selected precisely.
- Malformed input to several verifiers now fails closed with a typed pki.errors.PkiError instead of a raw TypeError: a signer or issuer distinguished name carrying an embedded control byte (the RFC 5280 section 7.1 name comparison, CVE-2009-2408) and oversized or malformed JSON are rejected with a domain error code across pki.cms.verify, pki.tsp.verify, pki.jose, pki.sigstore, and pki.webcrypto key import.

## v0.2.18 — 2026-07-14

Composite ML-DSA signatures join CMS SignedData: pki.cms.sign and pki.cms.verify now produce and verify a composite SignerInfo (a post-quantum ML-DSA paired with a traditional RSA, ECDSA, or EdDSA), accepted only when both components verify.

### Added

- pki.cms.verify verifies, and pki.cms.sign produces, a composite ML-DSA CMS SignerInfo (draft-ietf-lamps-cms-composite-sigs) pairing ML-DSA-44/65/87 with a traditional RSA (PKCS#1 v1.5 or PSS), ECDSA (P-256/384/521), or EdDSA (Ed25519) component. The signature is accepted only when both the post-quantum and traditional components verify over the domain-separated message representative; the digestAlgorithm is the parameter set's paired pre-hash, and the composite public-key OID must match the signatureAlgorithm. Fifteen algorithm arms verify and sign today; the two brainpool-curve arms and the one SHAKE256-pre-hash arm are recognized but fail closed to a typed error (their curve / digest is outside the WebCrypto surface).
- pki.cms.sign accepts a composite signer as { cert, key: { mldsa, trad } } (the two component private keys as PKCS#8), since a composite private key has no single native representation; it signs both components over the RFC 5652 section 5.4 preimage and emits the fixed-order composite signature the verifier consumes.

### Fixed

- EdDSA (Ed25519 / Ed448) public keys are validated as a canonical, on-curve, full-order Edwards point before any signature is verified with them, across certification-path validation (pki.path.validate, whether a certificate signature or a CRL / OCSP-response signature checked during revocation), composite CMS SignerInfo components, and JWS verification (pki.jose.verify). A low-order key (for example the identity point, which the underlying platform imports without complaint and which verifies a forged signature for every message) is rejected up front, so it can no longer certify a forged certificate chain, forge a CRL or OCSP response, satisfy the traditional half of a composite signature, or make a forged JWS verify. Certificate and revocation verification share one key-import routine, so the check cannot be applied to one surface and skipped on another.

## v0.2.17 — 2026-07-13

Post-quantum SLH-DSA joins CMS SignedData: pki.cms.sign and pki.cms.verify now sign and verify with all twelve FIPS 205 SLH-DSA parameter sets (RFC 9814), freely mixed with the classical and ML-DSA signers in one message.

### Added

- pki.cms.sign and pki.cms.verify sign and verify a CMS SignedData with the twelve pure FIPS 205 SLH-DSA parameter sets (id-slh-dsa-sha2-128s/f, -192s/f, -256s/f and the SHAKE equivalents), RFC 9814: pure mode, empty context, AlgorithmIdentifier parameters absent, over attached or detached content and single or multiple signers. An SLH-DSA signer mixes freely with RSA, RSASSA-PSS, ECDSA, EdDSA, and ML-DSA signers in one message. The signer identifier is issuerAndSerialNumber or subjectKeyIdentifier, and the output is a DER Buffer or PEM.
- The CMS message-digest algorithm for an SLH-DSA signer is fixed to the parameter set's paired digest (RFC 9814 section 4); signing emits it automatically and rejects a caller digest that contradicts the set, so the SignedData carries the conformant digest for the chosen parameter set.

### Changed

- CMS signature verification's one-shot signer-key agreement check (a single algorithm identifier naming both the key and the signature) now covers SLH-DSA alongside EdDSA and ML-DSA: an SLH-DSA SignerInfo whose signer certificate public-key parameter set disagrees with the signatureAlgorithm fails closed with a typed error.

## v0.2.16 — 2026-07-13

Post-quantum ML-DSA joins CMS SignedData: pki.cms.sign and pki.cms.verify now sign and verify with ML-DSA-44/65/87 (RFC 9882), freely mixed with the classical signers in one message.

### Added

- pki.cms.sign and pki.cms.verify sign and verify a CMS SignedData with the post-quantum ML-DSA-44, ML-DSA-65, and ML-DSA-87 (RFC 9882): pure mode, empty context, AlgorithmIdentifier parameters absent, over attached or detached content and single or multiple signers, freely mixed with RSA, RSASSA-PSS, ECDSA, and EdDSA signers in one message. The signer identifier is issuerAndSerialNumber or subjectKeyIdentifier, and the output is a DER Buffer or PEM.
- The CMS message-digest algorithm for an ML-DSA signer is held to the parameter set's security strength (RFC 9882 section 3.3): SHA-512 by default and SHAKE256 optional, with SHA-256 accepted only for ML-DSA-44. A below-strength digest is refused fail-closed on both signing and verification, so a weak message digest cannot cap the collision resistance of a strong ML-DSA signature.

### Changed

- CMS signature verification now requires a one-shot signer (EdDSA or ML-DSA, where a single algorithm identifier names both the key and the signature) to present a signer certificate whose public-key algorithm matches the SignerInfo signatureAlgorithm; a disagreement fails closed with a typed error and no longer surfaces as an opaque import failure.

## v0.2.15 — 2026-07-13

CMS SignedData signing arrives as pki.cms.sign, and RFC 3161 timestamp token creation as pki.tsp.sign: the producing sides of the CMS and timestamp verifiers, emitting exactly what pki.cms.verify and OpenSSL cms -verify accept.

### Added

- pki.cms.sign(content, signers, opts) produces a CMS SignedData (RFC 5652 section 5): attached or detached content, one or many signers, RSA (PKCS#1 v1.5 and, with opts.pss, RSASSA-PSS), ECDSA (P-256/384/521), Ed25519, and Ed448. Each signer is { cert, key } (a PEM/DER certificate and a WebCrypto CryptoKey or PKCS#8 key); the signed attributes (content-type, message-digest, signing-time, plus opts.additionalSignedAttributes) are canonical DER and the signature covers the exact section 5.4 preimage. opts selects detached content, the encapsulated content type, the signer identifier (issuerAndSerialNumber or subjectKeyIdentifier), certificate embedding, and DER or PEM output.
- pki.tsp.sign(messageImprint, tsa, opts) creates an RFC 3161 TimeStampToken over a message imprint ({ hashAlgorithm, hashedMessage }): a CMS SignedData whose content is a TSTInfo carrying the imprint, the TSA policy, a serial number, and genTime, with optional accuracy, nonce, and ordering, and the RFC 3161 section 2.4.2 / RFC 5816 signing-certificate (ESSCertIDv2) attribute binding the token to the TSA certificate. It composes pki.cms.sign, so any supported TSA key algorithm works.

## v0.2.14 — 2026-07-13

CMS SignedData signature verification arrives as pki.cms.verify, verifying a signed message (S/MIME, timestamps, code signing) over the exact RFC 5652 preimage, for attached and detached content, one or many signers, across RSA, RSASSA-PSS, ECDSA, and EdDSA.

### Added

- pki.cms.verify(input, opts) verifies a CMS SignedData signature (RFC 5652 section 5) for attached and detached content, single and multiple signers, across RSA, RSASSA-PSS, ECDSA, and EdDSA. It accepts a PEM string, a DER Buffer, or a parsed pki.schema.cms object; opts.content supplies the external content for a detached signature and opts.certs supplies additional signer certificates. Each signer is located by its issuerAndSerialNumber or subjectKeyIdentifier and its signature checked over the exact RFC 5652 section 5.4 preimage: the message-digest attribute bound to the content digest and the signature verified over the SignedAttributes re-encoding when signed attributes are present, otherwise over the content directly. Returns { valid, signers } with a per-signer verdict and the matched certificate; a false verdict or a structural fault is a fail-closed cms/* outcome.

## v0.2.13 — 2026-07-13

The certificate linter validates IP-literal common names with a strict in-house checker instead of node:net, so the toolkit pulls in no networking module.

### Changed

- pki.lint validates an IP-literal common name with a strict in-house IPv4/IPv6 checker (lib/ip-utils) instead of node:net, so the toolkit needs no networking module; the validator now also recognizes IPv4-mapped and dual-stack IPv6 literals.

## v0.2.12 — 2026-07-13

pki.ct.verifySct verifies a Signed Certificate Timestamp's signature against a Certificate Transparency log's public key.

### Added

- pki.ct.verifySct(entry, sct, logPublicKey) verifies a Signed Certificate Timestamp's signature against a CT log's public key (RFC 6962 section 3.2), composing pki.ct.reconstructSignedData, the shared ECDSA-Sig-Value conformance gate, and pki.webcrypto. Resolves true/false on the cryptographic verdict; throws a typed CtError on a structural fault.

## v0.2.11 — 2026-07-13

The pki command-line tool gains inspect, lint, convert, and verify: front-ends over the certificate inspector, the linter, the PEM codecs, and RFC 5280 path validation.

### Added

- pki inspect <cert> renders a certificate as an openssl x509 -text style report (composes pki.inspect.certificate).
- pki lint <cert> [--profile <name>] [--severity <floor>] [--json] lints a certificate against the RFC 5280 and CABF TLS profiles, exiting non-zero when an error or fatal finding is present (composes pki.lint.certificate).
- pki convert <file> --to der|pem [--label <label>] transcodes between DER and PEM with auto-detected input encoding and byte-exact round-tripping.
- pki verify <cert>... --anchor <cert> [--time <ISO>] validates an ordered certification path against a trust anchor per RFC 5280 section 6.1 (composes pki.path.validate), exiting non-zero and naming the failing check on rejection.

## v0.2.10 — 2026-07-13

Certificate linting arrives as pki.lint: graded, advisory conformance findings against the RFC 5280 profile and a representative CA/Browser Forum TLS Baseline Requirements subset.

### Added

- pki.lint.certificate(input, opts) lints a certificate against the RFC 5280 profile and a representative CA/Browser Forum TLS BR subset, returning a report of graded advisory findings (id, severity, source, spec citation, message). The data path never throws: malformed input becomes a fatal lint/unparseable finding instead of an exception, so a corpus lints without per-file error handling; only config-time misuse raises a typed LintError.
- pki.lint.rules(profile) and pki.lint.profiles() enumerate the rule registry and the available profiles (rfc5280, cabf-tls) so findings are traceable to a stable id and a spec clause.

## v0.2.9 — 2026-07-13

Certification-path validation verifies composite ML-DSA signatures, accepting a certificate only when both its post-quantum and traditional components verify.

### Added

- pki.path.validate verifies composite ML-DSA certificate signatures (draft-ietf-lamps-pq-composite-sigs): a post-quantum ML-DSA paired with a traditional RSA / ECDSA / EdDSA, accepted only when both components verify over the domain-separated message representative, an all-components-must-verify rule (an OR would be a downgrade). The same combinator verifies a composite-signed CRL or OCSP response. Proven against the draft's official known-answer test vectors.
- The 18 composite algorithm identifiers (1.3.6.1.5.5.7.6.37-54) are registered in the OID registry and their AlgorithmIdentifier parameters-absent requirement is enforced across every format that carries a signature algorithm.

## v0.2.8 — 2026-07-13

pki.webcrypto rejects an AES key of invalid length at import instead of deferring the failure to first use.

### Fixed

- pki.webcrypto.subtle.importKey now rejects a raw or JWK AES key whose length is not 128, 192, or 256 bits as a webcrypto/data DataError at import, where it previously returned a CryptoKey that only failed at first use. Covers AES-GCM, AES-CBC, AES-CTR, and AES-KW; HMAC, HKDF, and PBKDF2 keys are unaffected.
- The README capability table and the documentation site render the certificate-inspection entry correctly: an inline code span containing pipe characters no longer breaks the surrounding table into misaligned columns.

## v0.2.7 — 2026-07-13

pki.webcrypto rejects an imported key whose type disagrees with its algorithm, and reports every cipher fault as a typed error.

### Changed

- The pkijs.com documentation site is regenerated with content-hashed CSS/JS under a strict Content-Security-Policy, an in-memory search endpoint, a browsable reference of every error class and code, symbol autocomplete, and concept guides. Documentation only; the published package is unchanged.

### Fixed

- pki.webcrypto.subtle.importKey now validates that an imported asymmetric key's actual type matches the requested algorithm (an RSA key imported under an Ed25519, ECDSA, or RSA-PSS name is rejected as webcrypto/data), closing an algorithm-confusion path where a mislabeled CryptoKey could later be used under the wrong signature scheme. The EC import path already derived and checked the curve; this extends the same key-is-authority rule to RSA and the Edwards/Montgomery curves.
- pki.webcrypto AES cipher faults now fail closed with a typed webcrypto/operation error instead of a raw Node exception: a decrypt of a tampered AES-GCM ciphertext (failed authentication tag), bad AES-CBC padding, a non-8-byte-multiple AES-KW wrap/unwrap length, and a malformed cipher parameter all surface as a WebCryptoError, so a caller catching pki.errors.PkiError sees a typed verdict and no bare Node error crosses the API boundary.

## v0.2.6 — 2026-07-12

WebAuthn attestation verification covers Ed448 and the RFC 9864 fully-specified COSE algorithms, and hardens credential-key conformance.

### Added

- pki.webauthn now verifies the RFC 9864 fully-specified COSE algorithm identifiers a WebAuthn relying party may receive: ESP256 (-9), ESP384 (-51), ESP512 (-52), Ed25519 (-19), and Ed448 (-53). Ed448 (-53) is the only WebAuthn path to Ed448, so an Ed448 credential now verifies where it previously errored as an unsupported algorithm.
- The verifier now runs against the official W3C WebAuthn Level 3 test-vector suite as an independent cross-implementation oracle: every published vector across ES256 / ES384 / ES512 / RS256 / Ed25519 / Ed448 and the packed / self / tpm / apple / fido-u2f / none formats.

### Changed

- A WebAuthn credential key with COSE alg -8 (EdDSA) now requires curve Ed25519 (crv 6), matching the WebAuthn algorithm-identifier profile; an -8 key claiming Ed448 (crv 7) is rejected; Ed448 is carried under the fully-specified identifier -53 instead.
- An EC2 credential key must use the uncompressed point form; the compressed sign-bit y encoding is rejected for WebAuthn credential keys.

### Fixed

- The WebAuthn credential public-key point is now validated on its curve, so an off-curve or identity EC/Edwards point fails closed at decode and is never carried into a later verify step.
- An ECDSA attestation signature is now enforced as a minimally-encoded DER ECDSA-Sig-Value (X.690): a non-minimal, negative, zero, or over-size r/s coordinate is rejected as malformed instead of being stripped and accepted.

## v0.2.5 — 2026-07-12

WebAuthn / passkey attestation verification joins the toolkit as pki.webauthn.

### Added

- pki.webauthn.parseAttestationObject(bytes) structurally decodes a WebAuthn attestation object (the CBOR { fmt, attStmt, authData }) and its authenticatorData over the strict pki.cbor codec, returning the format id, the decoded rpIdHash / flags / signCount, the attested credential data (aaguid, credentialId, and the decoded COSE credentialPublicKey), and the raw authenticatorData bytes a signature covers. Malformed input throws webauthn/bad-attestation-object. W3C WebAuthn Level 3.
- pki.webauthn.verify(attestationObject, clientDataHash, opts) verifies a WebAuthn attestation statement (packed, tpm, android-key, apple, fido-u2f, or none), checking the attestation signature over authenticatorData || clientDataHash and each format's structural bindings (the x5c leaf key, the apple nonce, the tpm certInfo Name / extraData over the pubArea, the android KeyDescription, the fido-u2f verificationData), binding each attestation certificate key to the credential public key, and enforcing each format's certificate requirements (a packed leaf's Authenticator Attestation subject and non-CA basic constraints, a tpm AIK's empty subject and non-CA constraints). It resolves the attestation type and trust path or throws a typed webauthn/* error; a signature that does not verify is a webauthn/verify-failed verdict, never a silent pass. The error taxonomy gains WebauthnError (webauthn/*). W3C WebAuthn Level 3, RFC 9052.
- The OID registry gains the FIDO id-fido-gen-ce-aaguid, Android key-attestation, Apple anonymous-attestation, and TCG TPM (AIK key purpose, tpmManufacturer / tpmModel / tpmVersion) arcs that WebAuthn attestation certificates carry.

### Changed

- The bounded big-endian byte cursor under pki.ct's TLS-vector decoding is extracted to a shared engine primitive so the packed big-endian TPM structures in pki.webauthn read through the same bounds-before-slice cursor: one definition of the length-checked read, carrying each caller's typed error domain.

## v0.2.4 — 2026-07-12

Human-readable certificate inspection joins the toolkit as pki.inspect.

### Added

- pki.inspect.certificate(input) renders a certificate (a PEM string, a DER Buffer, or a pki.schema.x509.parse result) as a human-readable OpenSSL-x509-text-style report, composed over the strict X.509 parser, the shared RFC 5280 extension decoders, and the two-way OID registry. Standard extensions (basic constraints, key usage, extended key usage with purpose names, subject/issuer alternative names, subject and authority key identifiers, and more) decode to their content; an extension with no decoder is named from the registry and shown as its string or a hex dump. A value that is not a certificate, DER, or PEM throws inspect/bad-input; malformed certificate bytes throw inspect/bad-certificate; a malformed single extension never sinks the report. The error taxonomy gains InspectError (inspect/*). RFC 5280.

## v0.2.3 — 2026-07-12

Offline Sigstore bundle verification joins the toolkit as pki.sigstore.

### Added

- pki.sigstore.verifyBundle(bundle, opts) verifies a Sigstore bundle offline against caller-supplied trust material (opts.fulcioRoots, the Fulcio CA certificates; opts.rekorKeys, the Rekor log public keys, each with an optional validFor window honored against the log time so a rotated-out key is not used; optional opts.identity policy and opts.time). It returns { verified: true, payload, statement, subjects, predicateType, predicate, identity, integratedTime } on success (payload being the raw verified envelope bytes, never a re-serialization), and throws a typed sigstore/* error on any leg's failure. The transparency-log entry is bound to both the bundle signature and its leaf certificate, and only the v0.1-v0.3 bundle versions this release verifies are accepted (a newer version is recognized and deferred). pki.sigstore.parseBundle(input) decodes and structurally validates a bundle (object, JSON string, or Buffer) fail-closed. pki.sigstore.pae(payloadType, payloadBytes) builds the DSSE Pre-Authentication Encoding a signature covers. DSSE / Sigstore bundle v0.3 / RFC 9162 / SLSA provenance v1.
- The OID registry gains the Fulcio (Sigstore) certificate-extension arc 1.3.6.1.4.1.57264.1.* (the OIDC issuer, build-signer and source-repository identity claims), honoring the raw-string-vs-DER-UTF8String encoding split by member. The error taxonomy gains SigstoreError (sigstore/*): a malformed or oversize bundle (sigstore/bad-bundle), an unknown media type (sigstore/bad-bundle-version), an unsupported content arm (sigstore/unsupported-content), a DSSE signature that does not verify under the Fulcio leaf key (sigstore/dsse-verify-failed), an inclusion proof that does not reconstruct the tree root (sigstore/inclusion-proof-mismatch) or is malformed (sigstore/bad-inclusion-proof), a tree root not attested by the Rekor key (sigstore/unsigned-root), a log time not attested by the Rekor SET that signs it (sigstore/unattested-time, so an attacker cannot backdate the ephemeral Fulcio certificate into validity), a Fulcio chain that does not terminate at a caller-supplied trust anchor (sigstore/chain-incomplete) or fails validation as of the log time (sigstore/chain-invalid), an undecodable certificate identity (sigstore/bad-certificate), a malformed transparency-log entry (sigstore/bad-tlog-entry), a log entry that does not bind this signature (sigstore/entry-mismatch), an identity that fails the caller policy (sigstore/identity-mismatch), a payload that is not the expected in-toto statement (sigstore/bad-statement), and a predicateType that does not match a caller-pinned one (sigstore/predicate-mismatch). Fulcio CA anchors and Rekor keys honor their trusted-root validity windows so a rotated-out key or CA is not used, and every anchor sharing a subject DN is tried.

## v0.2.2 — 2026-07-11

Hybrid Public Key Encryption (RFC 9180) joins the toolkit as pki.hpke.

### Added

- pki.hpke.setupS(suiteIds, recipientPublicKey, opts) / pki.hpke.setupR(suiteIds, enc, recipientPrivateKey, opts) establish a sender / recipient HPKE context (RFC 9180 sec. 5.1); the returned context exposes seal(aad, pt) / open(aad, ct) with the sequence-counter nonce and a message-limit guard, and export(exporterContext, L) for the secret-export interface. pki.hpke.seal / pki.hpke.open are the single-shot wrappers (sec. 6). pki.hpke.suites carries the RFC 9180 sec. 7 KEM / KDF / AEAD / MODE code points. Keys are node KeyObjects or serialized bytes; the offered suites are DHKEM P-256, P-521, X25519, and X448, HKDF-SHA256 / HKDF-SHA512, the three AEADs plus export-only, and all four modes. RFC 9180.
- The error taxonomy gains HpkeError (hpke/*): a malformed, low-order, or otherwise invalid encapsulated or KEM key (hpke/bad-key, so a Diffie-Hellman that fails during derivation surfaces as a typed error, never a raw fault), an unknown or unsupported ciphersuite code point (hpke/unknown-suite, never a silent default), an unsupported mode (hpke/unknown-mode, so an out-of-registry mode is rejected before the key schedule), an authenticated mode invoked without the sender's key (hpke/auth-key-required), inconsistent PSK inputs (hpke/inconsistent-psk), an AEAD tag that does not verify (hpke/open-failed, returning no plaintext), a sequence-number overflow (hpke/message-limit, before any nonce reuse), a seal/open against an export-only suite (hpke/export-only), and a wrong-direction context call (hpke/wrong-role, so a recipient context cannot seal nor a sender context open; they share a key and base nonce).

## v0.2.1 — 2026-07-11

Stateful hash-based signature verification (HSS/LMS) joins the toolkit as pki.shbs.

### Added

- pki.shbs.verify(publicKey, message, signature) verifies an HSS (Hierarchical Signature System) signature, the wire form RFC 9802 (X.509) and RFC 9708 (CMS) carry for id-alg-hss-lms-hashsig, returning true only if every level of the hierarchy verifies. pki.shbs.verifyLms(publicKey, message, signature) verifies a single-tree LMS signature (the component HSS composes, and a standalone algorithm). Both take the raw octet blobs the parsers surface (a certificate's subjectPublicKeyInfo.publicKey.bytes, tbsBytes, and signatureValue.bytes); a malformed blob (bad length, an unknown or unapproved typecode, truncation, a typecode the public key does not commit to) throws a typed ShbsError, and a well-formed but wrong signature returns false. RFC 8554 / RFC 9802 / RFC 9708 / NIST SP 800-208.
- The OID registry gains id-alg-hss-lms-hashsig (1.2.840.113549.1.9.16.3.17), id-alg-xmss-hashsig, and id-alg-xmssmt-hashsig, all with parameters MUST be absent (RFC 9802 sec. 4). A stateful-hash-signature AlgorithmIdentifier carrying any parameters now fails closed at the shared algorithm-identifier gate, inherited by every format the toolkit parses. The error taxonomy gains ShbsError (shbs/*).

### Changed

- XMSS / XMSS^MT verification and automatic HSS/LMS verification inside pki.path.validate are not in this release; see the roadmap. The former awaits an authoritative interoperability test vector (RFC 8391 ships none and NIST ACVP does not yet cover XMSS); the latter awaits a real HSS-signed certificate to prove the certification-path wiring end to end. Operators verify today by handing the raw certificate / CMS blobs to pki.shbs.verify directly.

## v0.2.0 — 2026-07-11

Trust-store ingestion, sharded-CRL revocation, and a hardened input-guard layer.

### Added

- pki.trust.parseCertdata(text) and pki.trust.parseCcadbCsv(text) parse the Mozilla/NSS certdata.txt object stream and the CCADB All Certificate Records CSV into one Anchor shape carrying the exact { name, publicKey, algorithm, parameters } fields pki.path.validate consumes, plus per-purpose distrustAfter dates, delegator purposes (only CKT_NSS_TRUSTED_DELEGATOR grants a purpose), subjectDer, label, and mozillaCaPolicy. Certificate and trust objects are paired by byte-exact issuer + serial (never adjacency) and cross-checked against the parsed DER, so metadata can never attach to the wrong root. pki.trust.anchor(entry, { purpose }) hands the anchor to validate, failing fast when the entry does not delegate the purpose. Malformed octal, an oversized block or file, an unrecognized trust value, an undecodable distrust date, or a mispaired object throws a typed trust/* error. Offline and pure: the caller supplies the text; nothing fetches.
- pki.path.validate gains opts.checkPurpose plus trust-anchor constraint enforcement: with an anchor carrying distrustAfter / purposes metadata, a leaf whose notBefore is strictly after the anchor's distrust date for the checked purpose fails with path/distrusted-after (the boundary instant stays trusted, matching Mozilla's enforcement), and a purpose the anchor does not delegate fails with path/purpose-not-trusted. Anchors without the metadata validate exactly as before.
- cRLDistributionPoints and freshestCRL certificate-extension decoders, and RFC 5280 sec. 6.3.3 distribution-point correspondence in pki.path.crlChecker: a partitioned CRL whose critical issuing-distribution-point shares an identically-encoded name with one of the certificate's distribution points, carries no reason restriction on either side, is current, and verifies now establishes a good status for its shard. A non-corresponding, reason-restricted, non-critical-IDP, delta, or unverifiable shard keeps failing closed to undetermined. A listed serial still reports revoked regardless of correspondence.
- pki.asn1.decode and pki.cbor.decode accept a maxItems option (default C.LIMITS.DER_MAX_ITEMS) capping the total decoded elements, so a small dense input cannot fan out into an unbounded node tree (asn1/too-many-items). OCSP responses are capped at C.LIMITS.OCSP_MAX_CERTS embedded certificates (ocsp/too-many-certs), bounding the pre-authentication signature work an attacker-supplied response can demand.
- Strict JWK oct key-material decoding: importKey / unwrapKey reject a JWK oct key whose k member is missing, empty, padded, or non-canonical base64url instead of importing a wrong or empty key, and JSON key unwrap rejects duplicate members at every depth so a smuggled second parameter can no longer resolve last-wins. Unwrapped JWK text is bounded (size, nesting depth, strict UTF-8).

### Changed

- OID string handling is canonical everywhere: pki.asn1.build.oid and pki.oid.toDER reject a leading-zero arc (previously accepted and silently encoded as a different OID: "2.05.29.15" emitted the DER of 2.5.29.15), and pki.oid.toArcs / register now enforce the X.660 arc bounds on the string form (a root above 2, or a second arc above 39 under roots 0 and 1, can never be DER-encoded and now throws oid/bad-arc). Error codes consolidated with the canonical form: a one-arc or non-numeric-arc string throws oid/bad-input (previously oid/too-short and oid/bad-arc; oid/too-short is removed).
- pki.jose and WebCrypto JWK unwrap JSON limits are enforced through one shared bounded reader; an unwrapped-key JSON parse failure reports the typed webcrypto/data error without a nested SyntaxError cause.

### Fixed

- Signing via pki.jose over a payload backed by a detached ArrayBuffer now fails closed with a typed error instead of silently signing an empty payload; PEM encoding and EST transfer encoding reject a detached or non-buffer input the same way.
- EST server-side key generation rejects an EnvelopedData whose encryptedContent is present but zero-length (est/bad-key-part); previously only the fully absent form was rejected, so an empty ciphertext could reach the caller's decrypt step. The same shared check now backs the CRMF encrypted-key proof-of-possession and PKCS#12 paths.
- An attribute certificate whose objectDigestInfo digest is not octet-aligned is rejected at parse (attrcert/bad-object-digest-info) instead of surfacing a bit-truncated digest.
- A malformed content-type attribute value inside AuthEnvelopedData authenticated attributes surfaces cms/bad-content-type-attr instead of a raw asn1/* codec error.
- pki.path.validate rejects fractional maxPathCerts / maxPolicyNodes values (path/bad-input) instead of silently tolerating them, and validates requiredEku / userInitialPolicySet entries as canonical OID strings at the entry point; a leading-zero or out-of-bounds key could never match decoder output and now fails at boot instead of silently never matching.

## v0.1.32 — 2026-07-11

OCSP-backed revocation checking joins certification-path validation.

### Added

- pki.path.ocspChecker(responses) -> RevocationChecker builds an OCSP-backed revocation checker for pki.path.validate's revocationChecker option from a set of pre-fetched OCSP responses (DER Buffer, PEM string, or already-parsed). It matches the full CertID triple against the certificate under whichever hash algorithm the CertID declares, authorizes the responder (issuing CA or a CA-issued id-kp-OCSPSigning delegate), verifies the response signature over tbsResponseData, and enforces thisUpdate/nextUpdate currency, reporting good, revoked (with revocationReason), or unknown. A wrong-issuer CertID, an unauthorized responder, a stale, not-yet-valid, or nextUpdate-less response, a non-successful responseStatus, or any verification failure yields unknown, which the validator fails closed unless softFail is set. RFC 6960.

## v0.1.31 — 2026-07-11

The DER format cohort and the JOSE surface graduate to stable.

### Changed

- pki.schema.pkcs12 / attrcert / crmf / cmp / csrattrs (parse, pemDecode, pemEncode), pki.schema.all and pki.schema.parse, and the pki.jose signing / verification / thumbprint / base64url / JSON surface graduate from experimental to stable.
- The LTS-CALENDAR graduation criterion now states that a settled, well-tested format no mainstream tool implements graduates on the toolkit's own conformance-vector round-trip plus coverage-guided fuzzing, since no harness oracle exists for it.

## v0.1.30 — 2026-07-11

Fail-closed hardening of the byte-input and text-decode boundaries.

### Changed

- A detached-backed BufferSource, a transferred or structuredClone'd view, no longer decodes as an empty buffer in a DER format parser: pki.schema.x509 / crl / csr / pkcs8 / cms / pkcs12 all fail closed with the format's typed bad-input error at the shared parse-input boundary.

### Fixed

- The EST transfer and multipart-mixed decoders enforce their size cap on the raw byte length before decoding the payload to a string, and an HTTP error response body is decoded only up to the prefix shown in the message, closing a single-input string-allocation amplification where an oversized body was materialized in full before the cap rejected it.
- pki.oid.fromDER rejects a non-Buffer or detached-backed input with a typed oid/bad-input error instead of a raw TypeError.

## v0.1.29 — 2026-07-10

A detached-backed BufferSource now fails closed with a typed error at every byte-input boundary.

### Fixed

- pki.webcrypto digest / sign / verify no longer silently process a detached-backed Buffer as empty input (a fail-open where a transferred backing ArrayBuffer left the view zero-length); a detached BufferSource is now rejected with a typed webcrypto/data error, as is getRandomValues.
- pki.asn1.decode, pki.cbor.decode, and pki.ct.parseSctList reject a detached-backed Buffer or view with a typed error (asn1/not-buffer, cbor/not-buffer, ct/bad-input) instead of a raw TypeError or a misleading truncated-input verdict. The underlying byte-view failure is threaded as the error cause.

## v0.1.28 — 2026-07-10

Merkle transparency proof verification joins the toolkit as pki.merkle.

### Added

- pki.merkle.leafHash / nodeHash / emptyRootHash -- the RFC 6962 / RFC 9162 tree hashes: a leaf is SHA-256(0x00 || entry), an interior node is SHA-256(0x01 || left || right), the empty tree is SHA-256(""). The domain-separation prefixes are applied unconditionally.
- pki.merkle.verifyInclusion({ leafIndex, treeSize, leafHash, proof, rootHash }) -- verify an RFC 6962 / RFC 9162 audit proof by folding the leaf up the audit path and constant-time-comparing the reconstructed root to a trusted root. Returns true only when the proof binds the leaf to the root.
- pki.merkle.verifyConsistency({ oldSize, newSize, oldRoot, newRoot, proof }) -- verify an append-only consistency proof by reconstructing both the old and the new root and constant-time-comparing each; the append-only guarantee lives in the old-root leg.
- The error taxonomy gains MerkleError (merkle/*). A node-count ceiling (C.LIMITS.MERKLE_MAX_PROOF_NODES) rejects a pathologically long proof before any hashing; the precise per-proof guard is the geometry check in each verifier.
- Fuzz target merkle-verify (both fold algorithms and the hash producers over adversarial coordinates, hashes, and proofs) joins the per-PR and nightly fuzz matrices with a seed corpus.

## v0.1.27 — 2026-07-10

A strict deterministic-CBOR codec joins the toolkit as pki.cbor.

### Added

- pki.cbor.decode -- the RFC 8949 core-deterministic CBOR decoder. It returns a node carrying the major type, the argument (a lossless BigInt), zero-copy content / bytes views (the raw ranges an external verifier hashes), and children (array elements, ordered map key/value pairs, or a tag's one inner item). Every non-canonical shape fails closed with a stable cbor/* code; maxBytes, maxDepth, maxItems, and a per-bignum byte cap bound the work before allocation (so a container declaring millions of tiny elements fails closed before memory is exhausted); allowTrailing decodes the first item of a CBOR Sequence.
- The read.* leaf readers over a decoded node: read.uint / read.nint / read.int (uniform BigInt), read.byteString (zero-copy Buffer), read.textString (strict UTF-8), read.array, read.map (ordered key/value node pairs), read.boolean / read.nullValue / read.undefinedValue, read.float (half / single / double), and the tagged forms read.biguint (RFC 8949 tag 2 unsigned bignum, minimality and byte cap enforced), read.time (RFC 8949 tag 1 epoch time, bounded to the valid Date range), and read.oid (RFC 9090 tag 111, decoded through the shared OID-content codec so a malformed body surfaces the existing oid/* codes).
- The error taxonomy gains CborError (cbor/*). The decoder is profile-parameterized, so a future CTAP2 canonical profile arrives as data and needs no new code path.
- Fuzz target cbor-det-parse (the decode head-well-formedness and minimal-argument checks, the map ordering / uniqueness verify, the shortest-float rule, the strict-UTF-8 gate, and the size / depth / bignum caps, in both whole-buffer and CBOR-Sequence modes) joins the per-PR and nightly fuzz matrices with a seed corpus.

### Changed

- pki.oid.paramsMustBeAbsent graduated from experimental to stable: its dotted-OID-to-boolean surface has been unchanged since 0.1.21 and is exercised end-to-end by the algorithm-identifier decoder every format shares.

## v0.1.26 — 2026-07-10

Test-coverage measurement and the OpenSSF Best Practices badge.

### Added

- npm run coverage measures statement and branch coverage over the full test suite with c8. It is a development dependency only; the published package still declares zero runtime dependencies.

### Changed

- The README badge row now includes the OpenSSF Best Practices badge.

## v0.1.25 — 2026-07-10

ACME joins the toolkit: an RFC 8555 message layer over a new RFC 7515 JOSE surface.

### Added

- pki.jose — the RFC 7515 Flattened JWS and RFC 7638 JWK-thumbprint layer. jose.sign / jose.verify produce and check a Flattened JWS against one of three declarative profiles (ACME outer, EAB inner, keyChange inner) that carry the required and forbidden header rules as data, so sign and verify cannot diverge; jose.base64url is the strict RFC 4648 section 5 codec (a trailing '=', a '+' or '/', whitespace, or non-canonical trailing bits are rejected); jose.parseJson is a bounded recursive-descent reader that throws on a duplicate member at any nesting depth, on invalid UTF-8, and past the size or depth caps; jose.thumbprint is the RFC 7638 canonical SHA-256 thumbprint (RSA, EC, oct, OKP, and AKP member templates, optional members excluded).
- pki.acme — the RFC 8555 / 8737 / 8738 / 9773 ACME message layer over pki.jose. acme.validate checks a directory, account, order, authorization, challenge, or renewalInfo object against its spec (closed status enums, conditional-required fields such as a pending order's expires, URL and RFC 3339 shapes, non-empty arrays; unknown fields are ignored, never reflected); acme.validateProblem checks an RFC 7807 problem document and its subproblems (a top-level identifier is rejected); acme.assertTransition enforces the three section 7.1.6 state machines; acme.identify classifies an object into exactly one kind.
- ACME request builders: acme.newAccount (with a fail-closed mailto contact check) and acme.externalAccountBinding (an HMAC-only inner JWS over the account key); acme.newOrder (identifier validation with one leading wildcard label permitted for dns, and the RFC 9773 replaces field); acme.finalize, which parses the CSR with pki.schema.csr, requires its requested identifier set (SAN plus CN) to equal the order identifiers, and rejects a CSR whose public key is the account key (RFC 8555 section 11.1); acme.challengeResponse, acme.deactivate, acme.revokeCert (account-key or certificate-key signed, CRLReason range-checked), acme.keyChange (the section 7.3.5 nested JWS), and acme.postAsGet (an empty payload, distinct from an empty object).
- ACME challenge computations: acme.keyAuthorization (token plus the account-key thumbprint), acme.http01, acme.dns01 (the _acme-challenge record with one wildcard label stripped), and the tls-alpn-01 pair acme.tlsAlpn01Extension / acme.verifyTlsAlpn01, which build and check the critical id-pe-acmeIdentifier extension (a 32-octet Authorization equal to the SHA-256 of the key authorization) together with a single-entry SubjectAltName.
- ARI (RFC 9773): acme.ariCertId builds a certificate's renewal identifier from its authorityKeyIdentifier and serial content octets, preserving the serial's leading sign-padding byte so the identifier matches what a CA computes; acme.parseAriCertId decodes one back to its two halves; acme.validateRenewalInfo checks a suggestedWindow and rejects an inverted or zero-width window.
- The error taxonomy gains JoseError (jose/*) and AcmeError (acme/*); the OID registry gains id-pe-acmeIdentifier (RFC 8737).
- pkix.pemDecodeAll decodes an RFC 7468 multi-block PEM chain (CERTIFICATE label, no explanatory text between blocks, at least one block) beside the existing single-block pemDecode.
- Fuzz targets jose-parse (the base64url and JSON codecs and the JWS profile walk) and acme-object (the resource validators, identify, and the ARI certID parser) join the per-PR and nightly fuzz matrices with seed corpora.

## v0.1.24 — 2026-07-10

EST enrollment joins the toolkit: the RFC 8951 CSR-attributes parser and an RFC 7030 client-codec surface.

### Added

- pki.schema.csrattrs.parse(der) — decode EST CSR Attributes (CsrAttrs ::= SEQUENCE OF AttrOrOID, RFC 8951 section 3.5) into { items }. Each item is { kind, oid, name }, with kind 'oid' for a bare OBJECT IDENTIFIER or 'attribute' for an Attribute, which adds raw values plus, for the RFC 9908 meaningful types, a decoded view: extensions (id-ExtensionReq), curve / keySize (the EC / RSA key-type conventions), or template (the CertificationRequestInfoTemplate). An empty SEQUENCE is a complete valid document. Unknown OIDs / attribute types are tolerated (surfaced raw); the RFC 9908 semantic MUSTs fail closed with a typed CsrattrsError (at most one id-ExtensionReq whose value is a single Extensions, template version v1(0), a template carrying at most one id-aa-extensionReqTemplate and never both extension-request kinds). Registered in the format orchestrator (pki.schema.parse routes a CsrAttrs, including the empty SEQUENCE, to csrattrs).
- pki.est — the transport-agnostic RFC 7030 / 8951 / 9908 EST client surface. transferDecode / transferEncode are the RFC 8951 base64 transfer codec (RFC 4648, blind to any Content-Transfer-Encoding header, bounded before and after decoding). splitMultipartMixed splits the /serverkeygen multipart/mixed body (terminal boundary required, nested/extra parts rejected). parseCertsOnly validates a certs-only Simple PKI Response (RFC 5272 section 4.1) over cms.parse output (empty signerInfos, no eContent, plain X.509 certificates only), surfacing certificates raw and in as-received order. findIssuedCert picks the issued certificate by a public-key match (never a positional guess). parseServerKeygenResponse dispatches the two-part key + certificate response and enforces the request-to-response recipient-arm coherence. classifyResponse is the HTTP status / content-type / Retry-After state machine (a 202 surfaces retryAfterSeconds, never slept on; 204/404 on /csrattrs is a 'none available' verdict). paths builds the RFC 7030 operation URLs with the optional CA-label guard. The builders assemble the CSR attributes EST adds: challengePasswordFromTlsUnique (channel binding, 255-octet cap), decryptKeyIdentifierAttr / asymmetricDecryptKeyIdentifierAttr, smimeCapabilitiesAttr, buildEnrollAttributes (the RFC 9908 template-priority enroll plan), and reenrollGuard.
- The error taxonomy gains CsrattrsError (csrattrs/*) and EstError (est/*).
- The OID registry gains the RFC 4108 / RFC 7030 / RFC 9908 attribute identifiers: id-aa-decryptKeyID, id-aa-asymmDecryptKeyID, id-aa-certificationRequestInfoTemplate, and id-aa-extensionReqTemplate.
- Fuzz targets csrattrs-parse and est-transfer (the base64 + multipart codecs) join the per-PR and nightly fuzz matrices with seed corpora.

## v0.1.23 — 2026-07-09

CMS grows authenticated content: RFC 5652 AuthenticatedData, RFC 5083 AuthEnvelopedData, and RFC 9629 KEM recipients (ML-KEM ready), plus a toolkit-wide hardening pass.

### Added

- pki.schema.cms.parse decodes id-ct-authData (RFC 5652 section 9 AuthenticatedData): { version, originatorInfo, recipientInfos, macAlgorithm, digestAlgorithm, encapContentInfo, authAttrs, authAttrsBytes, mac, unauthAttrs }. The section 9.1 version rule is computed from originatorInfo contents (recipient kinds never influence it); digestAlgorithm and authAttrs are enforced as a biconditional; authAttrs are required for a non-id-data content type and must carry content-type (matching the eContentType) and message-digest; authAttrsBytes is the raw on-wire [2] TLV for the section 9.2 MAC re-tag.
- pki.schema.cms.parse decodes id-ct-authEnvelopedData (RFC 5083): { version, originatorInfo, recipientInfos, encryptedContentInfo, aead, authAttrs, authAttrsBytes, mac, unauthAttrs }. A recognized AES-GCM/CCM content-encryption algorithm gets its RFC 5084 parameters validated (present, nonce bounds of CCM 7..13 octets, ICV length from the allowed set and equal to the mac length, DEFAULT-omitted per X.690 11.5) and surfaced as aead: { kind, nonce, icvLen }; an unrecognized algorithm surfaces raw parameters with aead null.
- KEMRecipientInfo (RFC 9629) parsed under the OtherRecipientInfo id-ori-kem arm: { version, rid, ridType, kem, kemct, kdf, kekLength, ukm, wrap, encryptedKey } as kemri alongside the raw oriValue. version must be 0; kekLength must be 1..65535 and match a recognized AES key-wrap's KEK size; a recognized ML-KEM kem pins the exact FIPS 203 ciphertext length. An unrecognized oriType still surfaces raw (the ORI extension point); a recognized one is validated by content, never accepted on the type OID alone.
- The parameters-absent registry (pki.oid.paramsMustBeAbsent) gains ML-KEM-512/768/1024 (RFC 9936) and the three HKDF identifiers (RFC 8619), enforced once in the shared AlgorithmIdentifier schema so certificates, CMS, and every other format inherit the rule.
- RFC 5652 section 11 attribute placement rules, enforced everywhere attribute sets are parsed: content-type / message-digest / signing-time must not appear in unsigned, unauthenticated, or unprotected attribute sets; countersignature only in unsigned attributes. signing-time values are validated as single-valued Time; every countersignature value is validated as a SignerInfo whose signedAttrs carry message-digest and no content-type (RFC 5652 section 11.4), recursively.
- Every pki.schema.cms.parse result carries contentType (the dotted OID) and contentTypeName, naming which of the five content types was dispatched, so a consumer no longer duck-types the result shape.
- pemEncode lands on every remaining format: pki.schema.ocsp.pemEncode (default label OCSP RESPONSE), pki.schema.attrcert.pemEncode (ATTRIBUTE CERTIFICATE), pki.schema.crl.pemEncode (X509 CRL), and label-required pki.schema.tsp.pemEncode / pki.schema.crmf.pemEncode (no standard PEM label exists for those formats, so the operator names the envelope explicitly).
- New fuzz targets with seed corpora: crl-parse, csr-parse, pkcs8-parse, and schema-all-parse (the orchestrator front door), plus authenticated-content and KEM-recipient seeds for cms-parse; all wired into the per-PR and nightly fuzz matrices.
- pki.oid.register / registerFamily validate X.660 encodability at registration: root arc 0..2, second arc 0..39 under roots 0 and 1, at least two arcs, and no leading-zero components. A typo fails at config time instead of minting an unmatchable registry key.

### Changed

- SignedData and OriginatorInfo certificates/crls buckets validate the closed CertificateChoices / RevocationInfoChoice tag sets (RFC 5652 sections 10.2.1-10.2.2): elements are still surfaced raw, but a tag outside the CHOICE, or a primitive encoding, is rejected instead of silently feeding the version computation.
- Signed and authenticated attribute sets must be DER encoded even when the enclosing structure is BER (RFC 5652 sections 5.3/9.1, RFC 5083 section 2.1). An indefinite-length attribute set reaching the PKCS#12 public-key-integrity path is now rejected instead of surfacing re-tag bytes a verifier would hash incorrectly.
- Validity, TBSCertificate, and AttributeTypeAndValue assert their SEQUENCE tag (RFC 5280 section 4.1): a SET-tagged body no longer parses through pki.schema.x509.parse while the format orchestrator rejects the same bytes.
- issuerUniqueID / subjectUniqueID are decoded as the [n] IMPLICIT BIT STRING RFC 5280 section 4.1.2.8 defines; an EXPLICIT-wrapped or malformed unique identifier is rejected.
- The IssuingDistributionPoint decoder enforces the DER field grammar (strictly ascending tags, each at most once, DER BOOLEAN values, no encoded DEFAULT FALSE); a CRL whose IDP violates it has unknown scope and is unusable for revocation decisions.
- An empty embedded SEQUENCE is rejected wherever a Certificate / CertificateList is expected (OCSP certs lists, CMP, CRMF); CRMF encryptedKey proof-of-possession and PKCS#12 encrypted safes reject a zero-length ciphertext the same way as a missing one.
- RecipientEncryptedKey surfaces ridType (rKeyId | issuerAndSerialNumber) so a key-agreement consumer no longer duck-types the recipient-matching form.
- The pki.schema.cms.parse reference documentation describes all five decoded content types and their return shapes.

### Fixed

- Crypto engine: deriveKey implements the W3C get-key-length rules (AES lengths limited to 128/192/256, HMAC defaulting to the hash block size); deriveBits rejects over-length, zero, and non-multiple-of-8 requests against the actual shared-secret size; unwrapKey surfaces a typed error instead of a bare JSON.parse SyntaxError; an RSA publicExponent is bounds-checked before numeric narrowing.
- Path validation: an unreadable basicConstraints or issuer key-usage extension now fails the check that consulted it instead of being silently swallowed; name-constraint inputs are validated at the entry point; the policy-tree node budget is a documented constant (LIMITS.PATH_MAX_POLICY_NODES).
- ASN.1 codec: the constructed encodings of GeneralString, NumericString, and ObjectDescriptor are rejected in DER mode; the byte caps passed to asn1.decode are validated as finite non-negative integers.
- Publish pipeline: the npm tarball and SBOM are re-hashed against the attested SLSA subjects and verified with slsa-verifier before anything is signed, released, or published; eslint is lockfile-pinned and runs isolated from the pack workspace; gitleaks is version+checksum pinned; the OpenSSF Scorecard threshold gate fails closed when a score cannot be extracted.
- Every behavioral fix above ships with a conformance vector driving the public parse/validate surface on the malformed input.

## v0.1.22 — 2026-07-09

An RFC 5035 / RFC 8551 S/MIME ESS signed-attribute decoder joins the schema family.

### Added

- pki.schema.smime.parseSigningCertificate(der) / parseSigningCertificateV2(der) — decode the RFC 5035 ESS SigningCertificate (v1) and SigningCertificateV2 (v2) signed-attribute values into { certs, policies }. Each certs entry is { certHash, hashAlgorithm, issuerSerial } in wire order: certHash raw; hashAlgorithm the implied SHA-1 for v1, or the decoded algorithm (or the id-sha256 default, flagged defaulted) for v2; issuerSerial (or null) the issuer GeneralNames (each CHOICE arm validated, surfaced raw) plus serialNumber as a BigInt and serialNumberHex. certs is non-empty and order-preserving; a v2 hashAlgorithm encoded byte-equal to its DEFAULT is rejected smime/non-canonical-default (X.690 §11.5). Malformed input fails closed with a typed smime/* (or leaf asn1/*) code.
- pki.schema.smime.parseSmimeCapabilities(der) — decode an RFC 8551 SMIMECapabilities value into { capabilities }, an ordered list (preference order preserved, never sorted) of { capabilityID, name, parameters } with parameters the raw ANY-DEFINED-BY bytes.
- pki.schema.smime.decodeAttribute(attr) — an OID-dispatch convenience over the three decoders for a CMS-shaped { type, values } attribute (the shape cms.parse surfaces on signerInfos[i].signedAttrs). It enforces the single-AttributeValue rule (a values length other than one is rejected smime/multi-valued-attribute), routes on the attribute OID, and recognize-and-defers an unknown type as smime/unsupported-attribute carrying the type, registry name, and raw values.
- The error taxonomy gains SmimeError, carrying a stable smime/* code.
- The OID registry gains the smimeCapabilities attribute identifier and the RFC 2634 ESS attribute names (receiptRequest through contentReference), so a CMS signed attribute of one of those types resolves to a name in an unsupported-attribute diagnostic.

## v0.1.21 — 2026-07-09

SLH-DSA signatures verify in certification-path validation, and the post-quantum / EdDSA parameters-absent rule is enforced across every format.

### Added

- SLH-DSA signature verification in pki.path.validate — all twelve FIPS 205 parameter sets (id-slh-dsa-sha2-{128,192,256}{s,f} and the SHAKE sets). A certificate or CRL signed with SLH-DSA now verifies by importing the issuer's SLH-DSA public key and checking the one-shot signature over the raw signed region; the same rows serve both the certificate signature check and the CRL revocation checker. ML-DSA and the classical RSA / ECDSA / EdDSA set were already wired.
- pki.oid.paramsMustBeAbsent(oid) — a predicate that reports whether an AlgorithmIdentifier bearing the given OID must encode its parameters field as absent (the ML-DSA and SLH-DSA families and the RFC 8410 Edwards / Montgomery curves). It is the single source the shared AlgorithmIdentifier decoder consults.
- The OID registry now names the twelve pre-hash HashSLH-DSA identifiers (id-hash-slh-dsa-*, RFC 9909 §3), so a certificate or CRL that carries a HashSLH-DSA algorithm resolves to a name and is covered by the parameters-absent rule.

### Fixed

- The shared AlgorithmIdentifier decoder now rejects a present parameters field on the algorithms whose parameters MUST be absent, namely ML-DSA, SLH-DSA, Ed25519, Ed448, X25519, and X448 (RFC 9909 §3, RFC 9814 §4, RFC 9881 §2, RFC 8410 §3), failing closed with a <format>/bad-algorithm-parameters code. Previously a stray explicit NULL or arbitrary bytes in that field were surfaced raw. The rule is enforced once in the shared decoder, so every format that names an algorithm inherits it; a conforming identifier, which omits the field, is unaffected.
- Certification-path validation now enforces issuer-key / signature-algorithm consistency for the one-shot families whose public-key OID equals the signature OID (EdDSA, ML-DSA, and SLH-DSA), rejecting a mismatch with a path/algorithm-mismatch reason (RFC 9814 §4). Because the underlying WebCrypto import binds a public key of a different type to the requested algorithm name and verifies with the real key, a certificate or CRL signed by one key type but labeling its signatureAlgorithm as another one-shot type could otherwise validate; the check closes that algorithm-confusion path for both the certificate signature and the CRL revocation checker.

## v0.1.20 — 2026-07-09

An RFC 6962 Certificate Transparency SCT-list parser joins the toolkit.

### Added

- pki.ct.parseSctList(extValue) — RFC 6962 SCT-list parsing. It decodes the SignedCertificateTimestampList extension value (the raw extnValue content an x509 or OCSP extension surfaces) into { scts, unknownScts }. Each scts entry is a fully decoded v1 SCT: version (0), logId (32-byte Buffer) plus logIdHex, timestamp (exact BigInt) plus timestampMs (a Number, or null above 2^53) plus timestampDate, extensions (raw Buffer), the hashAlg / sigAlg code points plus a named signatureAlgorithm, the raw signature, and rawSct (the full SerializedSCT body). A SerializedSCT whose version is not v1 is preserved opaque in unknownScts as { version, rawSct } without failing the list (RFC 6962 §3.3 gives each SerializedSCT its own length so unknown versions are skippable). The extension value is the §3.3 double DER OCTET STRING wrap over a TLS-encoded list, decoded with a bounded reader that validates the list and per-SCT framing and every internal length, and asserts a per-list byte and count cap before it iterates. The signature is never verified and the log id never recomputed. Malformed input fails closed with a typed ct/* (or leaf asn1/*) code.
- pki.ct.reconstructSignedData(entry, sct) — rebuilds the exact digitally-signed preimage a verifier hashes to check an SCT's signature (RFC 6962 §3.2), for a decoded v1 SCT. entry selects the log-entry form: { entryType: 0, leafCert } for an SCT delivered over TLS or OCSP (signed over the leaf certificate), or { entryType: 1, tbsCertificate, issuerKeyHash } for an SCT embedded in a certificate (signed over the issuer key hash and the precertificate TBS). The preimage reuses the parsed SCT's raw extensions byte-for-byte; a verifier hashes the returned bytes and checks the signature with the log's public key.
- The certificate-extension value registry gains the SCT-list decoder and the precertificate-poison decoder (the poison value is tag-checked and its content validated as ASN.1 NULL).
- The OID registry gains the Certificate Transparency arc, covering the SCT-list, precertificate-poison, precertificate-signing-certificate, and OCSP SCT-list identifiers, so those extension OIDs resolve to names.
- The error taxonomy gains CtError, carrying a stable ct/* code.

## v0.1.19 — 2026-07-09

An RFC 9810 Certificate Management Protocol message parser joins the pki.schema family.

### Added

- pki.schema.cmp.parse(input) — RFC 9810 PKIMessage parsing. It decodes a DER Buffer or PEM into { header, headerBytes, body, bodyBytes, protection, extraCerts }. The header carries pvno (1..3), validated sender / recipient GeneralNames (the anonymous NULL-DN accepted), and the optional messageTime (GeneralizedTime only), protectionAlg, senderKID / recipKID, transactionID, senderNonce / recipNonce, freeText, and generalInfo (recognized id-it values are syntax-checked). The body is { arm, tag, bytes, decoded? }: ir / cr / kur / krr / ccr decode through the CRMF parser; ip / cp / kup / ccp decode to a certificate-response structure (an encrypted certificate's EnvelopedData decodes through the CMS parser; the deprecated EncryptedValue arm and caPubs surface raw, conferring no trust); krp decodes to a key-recovery structure ({ status, newSigCert, caCerts, keyPairHist }); rr / rp, genm / genp, error, certConf (an empty confirmation is the legal reject-all), and pollReq / pollRep decode structurally; pkiconf decodes to null; every other defined arm surfaces raw: p10cr, the challenge-response and announcement arms, and nested (never auto-recursed). certReqId values are big integers and accept the protocol's -1 sentinel. The two cross-field coherence rules (protection bits and protectionAlg present together or absent together; a certConf hashAlg requires version cmp2021) are enforced. Protection is surfaced; verifying it is the caller's job. headerBytes and bodyBytes are the exact wire slices, so a verifier reconstructs the protected part as a DER SEQUENCE wrapping them and checks the MAC or signature. Malformed input fails closed with a typed cmp/* or asn1/* code.
- pki.schema.cmp.pemDecode(text, label?) / pemEncode(der, label?) — PEM handling for messages that transit text channels (default label CMP).
- pki.schema.crmf.parse now surfaces every CertTemplate field, including serialNumber and the issuer/subject unique identifiers. RFC 4211's rule that a certificate request must omit the CA-assigned fields (serialNumber, signingAlg) and the deprecated unique identifiers moved from the shared CertTemplate structure to the request layer, so a request that sets them still fails closed while the same structure can identify an existing certificate, with serialNumber and issuer present, inside a CMP revocation.
- The OID registry gains the CMP id-it information types and the message-protection MAC algorithm identifiers (passwordBasedMac, dhBasedMac, kemBasedMac), so a parsed message's info types and protection algorithm resolve to names.
- The error taxonomy gains CmpError, carrying a stable cmp/* code.

### Changed

- pki.schema.tsp parsing (parse, parseTstInfo, parseToken, pemDecode) is now stable.
- The npm-publish vulnerability scan reads the committed lockfiles (the dev and build toolchain that runs during a publish) instead of the runtime SBOM, which is empty by construction because the package ships zero runtime dependencies.

### Fixed

- Certification-path validation bounds the BasicConstraints pathLenConstraint and the PolicyConstraints / InhibitAnyPolicy skip counts before narrowing them to a number, so a certificate carrying a value past the safe-integer range is rejected and the counter cannot round silently to the wrong value (the same exact-or-rejected rule the RSASSA-PSS salt length and PKCS#12 iteration count follow).
- Certification-path validation rejects a non-empty DER NULL in an RSASSA-PSS hash AlgorithmIdentifier's parameters. A NULL must carry empty content (X.690 8.8.2), so the previous tag-only check accepted a malformed encoding it now fails closed.

## v0.1.18 — 2026-07-08

An RFC 7292 PKCS#12 (PFX) store parser joins the pki.schema family.

### Added

- pki.schema.pkcs12.parse(input) — RFC 7292 PFX parsing. It decodes a DER / BER Buffer or PEM into { version, integrityMode, mac, macedBytes, authSafeSigned, safeBags, encryptedSafes }. Password-integrity stores surface { kind, hashOid, hashName, hashParameters, pbmac1, macValue, macSalt, iterations } plus macedBytes: the exact value octets the HMAC covers, excluding the octet-string header, so an external verifier hashes the correct region. The RFC 9579 PBMAC1 arm is validated as well as recognized: its parameters must be present, the key-derivation function must be PBKDF2 with a keyLength, and the decoded KDF (salt, iteration count, key length, PRF) and MAC scheme surface on pbmac1. The X.690 DEFAULT rule is enforced (an explicitly encoded iterations = 1 is non-canonical and rejects). Public-key-integrity stores surface the CMS SignedData and must carry at least one signer (the signature itself is verified externally). Each safeBag carries its type, friendlyName / localKeyId (decoded, single-value and single-instance rules enforced), and all attributes: keyBags delegate to pki.schema.pkcs8.parse, shrouded key bags to parseEncrypted (algorithm surfaced, ciphertext opaque), cert / CRL / secret values stay raw and byte-exact, and safeContentsBags recurse under a depth ceiling. Encrypted and enveloped safes are validated structurally by the CMS module with ciphertext kept raw, and must declare id-data (a SafeContents) as their encrypted content type. The version-3 rule, the contradictory MacData-alongside-SignedData combination, the closed bag-type and cert/CRL-type sets, and per-list element caps all fail closed with typed pkcs12/* codes; a MacData-less id-data store is legal syntax and parses as integrityMode "none".
- pki.schema.pkcs12.pemDecode(text, label?) / pemEncode(der, label?) — PEM handling for stores that transit text channels (default label PKCS12).
- pki.asn1.decode gains an opt-in ber option for formats whose content is normatively BER, accepting exactly two shapes: an indefinite length on a constructed value, and a constructed OCTET STRING whose segments reassemble into one primitive content. The default remains strict DER; minimal-length, minimal-integer, trailing-byte, and size / depth verdicts are unchanged in both modes, an indefinite length on a primitive value still rejects, a foreign-type segment inside a constructed string rejects, and constructed-string nesting is capped (each level re-copies its payload, so deep nesting amplifies memory without adding data).
- pki.schema.engine.embeddedDer(schema, bytes, ctx, opts) — the named form of the re-decode idiom: decode a fresh DER / BER blob carried inside an already-decoded value and walk it against a schema, wrapping codec failures in the caller's typed code. A shared budget option bounds how many nested blobs one parse may unwrap, so a container that chains encodings across octet-string boundaries cannot restart the depth caps from zero. The timestamp, OCSP, and certificate-request parsers now route their embedded-structure decodes through it.
- SEQUENCE OF / SET OF schemas can declare an element-count ceiling (max), so a container listing a great many tiny elements fails typed instead of amplifying memory through per-element parse products; a single attribute's value list is now capped this way across every format.
- The OID registry gains the PKCS#12 bag types, the PKCS#12 password-based encryption identifiers, the PKCS#9 certTypes / crlTypes / friendlyName / localKeyId entries, PKCS#5 PBKDF2 / PBES2 / PBMAC1, the NIST AES content-encryption arc, and the HMAC-with-SHA identifiers, so a store's algorithms resolve to names.
- The error taxonomy gains Pkcs12Error, carrying a stable pkcs12/* code.

### Changed

- The npm-publish workflow's vulnerability scan now scans the SBOM unconditionally and the vendored-bundle directory only when it holds a real bundle, so the scan is exact in both states instead of warning on the empty directory.

### Fixed

- Certification-path validation bounds the RSASSA-PSS saltLength and trailerField before numeric conversion, so an oversized value rejects with path/unsupported-algorithm instead of rounding silently on its way to the verifier, the same exact-or-rejected rule the PKCS#12 MAC parameters follow.

## v0.1.17 — 2026-07-06

An RFC 4211 certificate-request-message parser joins the pki.schema family.

### Added

- pki.schema.crmf.parse(input) — RFC 4211 CertReqMessages parsing. It decodes a DER Buffer or PEM into { messages: [ { certReq, popo, regInfo } ] }, where each certReq is { certReqId, certReqIdHex, certTemplate, controls, certReqBytes } and certTemplate carries the requestable fields version, issuer, validity, subject, publicKey, and extensions (each null when absent). RFC 4211 §5 requires a request to omit serialNumber and signingAlg (assigned by the CA) and issuerUID and subjectUID (deprecated); those fields are rejected and do not come back in the result, so a requester cannot dictate a CA-assigned value. issuer and subject Names are accepted in both the EXPLICIT and the IMPLICIT wire encodings; the OptionalValidity times are EXPLICIT UTCTime or GeneralizedTime; a supplied CertTemplate version must be 2; certReqId is an unbounded signed integer. popo is null, a raVerified marker, a decoded signature proof (with its poposkInput and signature surfaced raw), or a raw key-encipherment / key-agreement arm; for a signature proof, poposkInput's presence is checked against the template per §4.1. certReqBytes is the exact CertRequest byte range a proof-of-possession verifier hashes. Malformed input fails closed with a typed crmf/* or asn1/* code.
- pki.schema.crmf.pemDecode(text, label?) — extract the DER bytes from a PEM block (the first block unless a label is given).
- The OID registry gains the RFC 4211 registration-control (id-regCtrl) and registration-info (id-regInfo) identifiers on the id-pkip arc, so a parsed control or info entry resolves to its name (oldCertID, pkiArchiveOptions, utf8Pairs, and the rest).
- The error taxonomy gains CrmfError, carrying a stable crmf/* code.
- pki.schema.engine.encode(schema, value) — the constructor direction of the schema engine. A single declarative schema now drives both decode (walk, bytes to value) and encode (canonical DER, value to bytes): every leaf carries a read and a write, and EXPLICIT wrapping and IMPLICIT context-tag retagging are applied in one place, so an encoder can no longer emit a different tag than the decoder reads. A round-trip test proves walk(decode(encode(value))) recovers the value across universal, IMPLICIT, EXPLICIT, and SET-OF-ordered shapes, and the CRMF request format is proven to round-trip end to end.

### Changed

- pki.schema.ocsp request and response parsing (parseRequest, parseResponse, pemDecode) is now stable.
- An experimental primitive is surfaced for a graduation review once it has been experimental for a fixed number of releases; the review is recorded as a graduation to stable or a dated keep-experimental decision, so the experimental-to-stable-to-deprecated transition is driven on a schedule (see LTS-CALENDAR.md).

## v0.1.16 — 2026-07-06

Certification path validation joins the toolkit — RFC 5280 section 6, as a pure re-entrant algorithm.

### Added

- pki.path.validate(path, opts) — RFC 5280 section 6 certification-path validation. It validates an ordered array of pki.schema.x509.parse certificates (or DER/PEM it parses) against a trust anchor, running the section 6.1 state machine: section 6.1.3(a)(1) signature chaining, the always-on section 6.1.3(a)(2) validity window with the check date an explicit input, section 6.1.3(a)(4) name chaining, section 6.1.3(b,c)/6.1.4(g) name constraints (directoryName, dNSName, rfc822Name including an emailAddress carried in the subject DN, uniformResourceIdentifier, and iPAddress with the address-and-mask subtree form), section 6.1.4(k) basic constraints as the single authoritative CA gate, section 6.1.4(l,m) path length, section 6.1.4(n) keyUsage keyCertSign, and the section 6.1.3(d)/6.1.4(a,b,i,j)/6.1.5 certificate-policy tree with its explicit-policy, policy-mapping, and inhibit-any-policy counters. It returns { valid, path, results, workingPublicKey, workingPublicKeyAlgorithm, workingPublicKeyParameters, validPolicyTree } where results[i].checks carries a stable path/* reason code per check. Validation is pure and re-entrant. An unrecognized critical extension, an undetermined revocation status, or a structural fault fails the path with a typed code.
- pki.path.crlChecker(crls) — a CRL-backed revocation checker for the validate revocationChecker option, composing pki.schema.crl.parse. For each certificate it consults every CRL issued by the certificate's issuer (so a clean CRL cannot shadow a revoking one), verifies each CRL signature over its tbsBytes, honors the issuing-distribution-point scope and reason coverage, checks thisUpdate/nextUpdate currency, and requires the CRL signer to assert keyUsage cRLSign; a certificate listed in any authoritative in-scope CRL is revoked, and an issuer with no authoritative in-scope CRL yields an undetermined status, which the validator fails closed unless softFail is set. An OCSP checker satisfies the same interface.
- pki.schema.pkix gains the ns-parameterized RFC 5280 section 4.2.1 extension-value decoders (pkix.certExtensionDecoders) for basicConstraints, keyUsage, nameConstraints, certificatePolicies, policyMappings, policyConstraints, inhibitAnyPolicy, subjectAltName / issuerAltName, extKeyUsage, and authorityKeyIdentifier / subjectKeyIdentifier. Each turns a raw extension value into a validated structure or a typed error, fail-closed. The shared GeneralName validator gains a decoded-value mode (surfacing the IA5 text, the IP octets, or the directoryName as a structured name alongside the raw bytes) and an address-and-mask subtree-base mode for name-constraint bases; both are opt-in, so the existing callers are byte-identical.
- The OID registry gains the RFC 5280 policy and wildcard extension identifiers used by path validation: policyMappings, policyConstraints, and inhibitAnyPolicy, plus the anyPolicy and anyExtendedKeyUsage special-OID leaves.
- The error taxonomy gains PathError, carrying the per-check reason in its stable path/* code.

## v0.1.15 — 2026-07-06

CMS EnvelopedData and EncryptedData join the parser, and every documentation example is now executed as a test.

### Added

- pki.schema.cms.parse now decodes CMS EnvelopedData (RFC 5652 §6) and EncryptedData (§8). An EnvelopedData returns { version, originatorInfo, recipientInfos, encryptedContentInfo, unprotectedAttrs } with all five RecipientInfo kinds decoded: KeyTransRecipientInfo (§6.2.1, with the issuerAndSerialNumber/subjectKeyIdentifier version coupling enforced), KeyAgreeRecipientInfo (§6.2.2 + RFC 5753 §3.1), KEKRecipientInfo (§6.2.3), PasswordRecipientInfo (§6.2.4), and OtherRecipientInfo (§6.2.5). An EncryptedData returns { version, encryptedContentInfo, unprotectedAttrs }. The wrapped keys, the ciphertext, and all AlgorithmIdentifier parameters are surfaced raw: every recipient carries the keyEncryptionAlgorithm its encryptedKey must be unwrapped with, and a kekid / rKeyId OtherKeyAttribute is surfaced as raw DER. Decryption and key-unwrap are a separate layer. The CMSVersion is recomputed and enforced per structure and per recipient, recipientInfos is required non-empty, and the encryptedContent [0] IMPLICIT OCTET STRING is read as the ciphertext directly.
- The schema engine gains an implicitTag option on pki.schema.engine.seq() and on pki.schema.pkix.algorithmIdentifier(ns, { implicitTag }), a [tag] IMPLICIT SEQUENCE / AlgorithmIdentifier reader (used by the PasswordRecipientInfo keyDerivationAlgorithm [0]). A call with no option is byte-identical to before.
- Every @example in the documentation comment blocks is now executed end-to-end as a test (test/layer-0-primitives/doc-examples.test.js, in the smoke gate) instead of only being parse-checked: an example must run to completion or throw a typed PkiError, and every documented @primitive path must resolve to a real export, so a documented example can no longer drift from the shipped API. A new @originated comment tag records a callable's original availability version when its documented path is later corrected, enforced alongside the @since version gate.

### Changed

- The W3C WebCrypto constructor classes (CryptoKey, Crypto, SubtleCrypto, WebCryptoError) are now reachable under pki.webcrypto (e.g. pki.webcrypto.CryptoKey) alongside the ready Crypto instance, matching their documented path; the previously-separate pki.WebCrypto holder is removed.
- Repository tooling now installs npm packages exclusively through integrity-verified lockfiles: the fuzz build installs the jazzer.js engine via npm ci against the committed fuzz/package-lock.json, and the vendoring script resolves a package to an integrity-pinned lockfile in an isolated staging workspace (no install script runs, and the repo's own node_modules is never touched) before bundling. Tooling child processes that need a shell (the Windows npm shim) now receive one explicitly-quoted command string instead of an unescaped argument array.

### Fixed

- Two documented API paths that did not resolve at runtime are corrected: pki.webcrypto.CryptoKey (previously reachable only via pki.WebCrypto.CryptoKey) and pki.asn1.read.oid (its comment block labeled the path pki.asn1.readOid, which never existed). Both are now reachable at the documented path.
- A documentation example for pki.webcrypto.subtle.exportKey referenced an undefined variable; it now generates the key pair it exports.

## v0.1.14 — 2026-07-05

An RFC 5755 attribute-certificate parser joins the pki.schema family.

### Added

- pki.schema.attrcert — an RFC 5755 attribute-certificate parser. pki.schema.attrcert.parse turns a DER Buffer or PEM into a structured v2 attribute certificate ({ version, holder, issuer, signatureAlgorithm, serialNumber, serialNumberHex, validity, attributes, issuerUniqueID, extensions, tbsBytes, signatureValue }). The holder (baseCertificateID / entityName / objectDigestInfo) and issuer (v1Form / v2Form) identities come back as validated GeneralNames; the validity window is real Dates; the privilege attributes (id-at-role, id-aca-group, id-at-clearance, and any others) resolve by name where the registry knows them. The outer-equals-inner signatureAlgorithm agreement (RFC 5755 4.2.4), the positive-and-at-most-20-octet serialNumber (4.2.5), the GeneralizedTime-only validity (4.2.6), the non-empty unique-typed attribute list (4.2.7), and the digestedObjectType enumeration are all enforced fail-closed. pki.schema.parse detect-and-routes an attribute certificate; the obsolete v1 form is recognized and deferred with a precise attrcert/legacy-v1-not-supported.
- pki.schema.pkix gains a shared GeneralNames validator that the attribute-certificate parser composes for its four GeneralNames-bearing fields, validating every element as a well-formed GeneralName (rejecting a bad tag, a wrong primitive/constructed form, a non-IA5 string, or a mis-sized iPAddress). The sequence no longer surfaces as opaque bytes. It handles both a bare universal SEQUENCE OF GeneralName and a context-tagged IMPLICIT GeneralNames.
- The OID registry gains the RFC 5755 attribute-certificate object identifiers: the id-aca attribute-type family (authenticationInfo / accessIdentity / chargingIdentity / group), id-at-role and id-at-clearance, the id-ce-targetInformation and id-ce-noRevAvail extensions, and the id-pe-ac-auditIdentity / id-pe-aaControls / id-pe-ac-proxying private extensions, so a parsed attribute certificate's attributes and extensions resolve by name.

## v0.1.13 — 2026-07-05

An RFC 3161 timestamp parser joins the pki.schema family.

### Added

- pki.schema.tsp — an RFC 3161 timestamp parser. pki.schema.tsp.parse turns a DER Buffer or PEM into a TimeStampResp ({ status, statusString, failInfo, timeStampToken }) with the granted-carries-token / rejected-carries-none coupling enforced (tsp/missing-token, tsp/unexpected-token) and the PKIFailureInfo named bits decoded. pki.schema.tsp.parseToken parses a TimeStampToken by composing pki.schema.cms.parse and asserting the id-ct-TSTInfo content type (tsp/wrong-econtent-type), attached content (tsp/detached-token), and the single (TSA) signer (tsp/multi-signer), returning the decoded TSTInfo plus the signer material. pki.schema.tsp.parseTstInfo decodes a bare TSTInfo. The TSTInfo mandatory version-1, the GeneralizedTime-only genTime, the accuracy 1..999 range, the ordering DEFAULT FALSE omission, and the PKIStatus 0..5 range are all enforced fail-closed. pki.schema.parse detect-and-routes a TimeStampResp.
- The codec and schema engine gain three composable primitives that TSP required: pki.asn1.read.integerImplicit / pki.schema.engine.implicitInteger(tag) (a context-tagged IMPLICIT INTEGER, for the Accuracy millis / micros fields); pki.schema.engine.implicitSeqOf(tag, item) (an order-preserving IMPLICIT SEQUENCE OF, the sibling of implicitSetOf without the SET ordering rule, for the extensions field); and RFC 3161 / X.690 §11.7 fractional-seconds GeneralizedTime support in pki.asn1.read.time (a '.'-separated, trailing-zero-free, Z-terminated fraction, surfaced at millisecond precision).
- The OID registry gains the id-kp extended-key-purpose family (including id-kp-timeStamping) and the id-aa S/MIME authenticated-attribute family (signingCertificate / signingCertificateV2 / timeStampToken), so a parsed TSA certificate's key purpose and a signer's ESS binding attribute resolve by name.

## v0.1.12 — 2026-07-05

SLH-DSA object identifiers corrected and completed to all twelve FIPS 205 parameter sets.

### Fixed

- SLH-DSA OID resolution — id-slh-dsa-shake-128s and id-slh-dsa-shake-256s were mapped to the arcs of id-slh-dsa-sha2-256s (.24) and id-slh-dsa-shake-128f (.27), so pki.oid.name / pki.oid.byName resolved them incorrectly. All twelve Pure SLH-DSA parameter sets (sha2-128s/128f/192s/192f/256s/256f and shake-128s/128f/192s/192f/256s/256f) are now registered at their correct arcs .20 through .31 per RFC 9909 §3; the previously-absent nine sets now resolve as well. WebCrypto SLH-DSA sign/verify was unaffected, since it selects by algorithm name and does not go through the OID registry.

## v0.1.11 — 2026-07-05

An OCSP request and response parser joins the pki.schema family.

### Added

- pki.schema.ocsp.parseRequest and pki.schema.ocsp.parseResponse — an OCSP request / response parser per RFC 6960 (§4.1 OCSPRequest, §4.2 OCSPResponse). parseRequest turns a DER Buffer or an 'OCSP REQUEST' PEM string into { tbsRequestBytes, version, requestorName, requestList, requestExtensions, optionalSignature }, each requestList entry carrying its CertID with the two issuer hashes raw. parseResponse turns a DER Buffer or an 'OCSP RESPONSE' PEM string into { responseStatus, responseBytes, basicResponse }; for a successful basic response, basicResponse carries { tbsResponseDataBytes, responderID, producedAt, responses, signatureAlgorithm, signature, certs } and each responses[i].certStatus is { type: 'good' | 'revoked' | 'unknown' } (a revoked entry adds its revocationTime and revocationReason). A malformed structure throws a typed OcspError (ocsp/*), an unsupported responseType throws ocsp/unsupported-response-type, and a leaf-level codec fault surfaces as asn1/*. pki.schema.ocsp.pemDecode handles the PEM envelope, and pki.schema.parse detect-and-routes both OCSP shapes.
- pki.asn1.read.nullImplicit and the pki.schema.engine.implicitNull(tag) leaf — read a context-tagged IMPLICIT NULL (the shape the OCSP CertStatus good [0] and unknown [2] arms take), the primitive-leaf sibling of implicitBitString and implicitOctetString. It rejects a constructed or non-empty context node fail-closed.
- An ocsp-parse coverage-guided fuzz harness joins the CI fuzzing matrix (jazzer.js + libFuzzer, per pull request and nightly), driving both OCSP entry points on mutated input.

## v0.1.10 — 2026-07-05

A CMS SignedData parser joins the pki.schema family; coverage-guided fuzzing now runs in CI.

### Added

- pki.schema.cms.parse — a CMS SignedData parser per RFC 5652 (§3 ContentInfo + §5 SignedData). It turns a DER Buffer or a 'CMS' PEM string into { version, digestAlgorithms, encapContentInfo, certificates, crls, signerInfos }. encapContentInfo.eContent is the raw content (or null when the signature is detached); each SignerInfo carries its raw signature and, when signed attributes are present, the on-wire signedAttrsBytes for external verification. The signer identifier is an issuerAndSerialNumber or a subjectKeyIdentifier, with the version-to-identifier rule (RFC 5652 §5.3) enforced, and a degenerate certificates-only SignedData (empty digest algorithms and signer infos) is accepted. A ContentInfo whose content type is not id-signedData throws cms/unsupported-content-type (a recognized PKCS#7 type) or cms/unknown-content-type; a malformed structure throws a typed CmsError (cms/*) and a leaf-level codec fault surfaces as asn1/*. pki.schema.cms.pemDecode / pemEncode handle the PEM envelope, and pki.schema.parse detect-and-routes a CMS message.
- pki.asn1.read.octetStringImplicit and the pki.schema.engine.implicitOctetString(tag) leaf — read a context-tagged IMPLICIT OCTET STRING (the shape the CMS SignerIdentifier subjectKeyIdentifier [0] takes), the primitive-leaf sibling of implicitBitString.
- Coverage-guided fuzzing in CI — a ClusterFuzzLite integration (.clusterfuzzlite/) plus pull-request and nightly-batch workflows run jazzer.js + libFuzzer against the pki.asn1.decode, pki.schema.x509.parse and pki.schema.cms.parse harnesses. A finding fails the run with the reproducer inline and uploads the crash input as an artifact. The integration is detectable by OpenSSF Scorecard's Fuzzing check.

### Fixed

- The OpenSSL interop runner counted a cross-check the oracle could not perform (for example, an OpenSSL predating ML-DSA) as a pass. Such a cross-check is now recorded as a skip and reported separately, so the interop pass count is not inflated by checks that never executed.

## v0.1.9 — 2026-07-05

A PKCS#8 private-key parser joins the pki.schema family.

### Added

- pki.schema.pkcs8.parse — a PKCS#8 PrivateKeyInfo / OneAsymmetricKey parser per RFC 5208 §5 and RFC 5958 §2. It turns a DER Buffer or a 'PRIVATE KEY' PEM string into { version, privateKeyAlgorithm, privateKey, attributes, publicKey }, where privateKey is the raw OCTET STRING content (the inner RSA/EC/curve key, decoded by the caller via privateKeyAlgorithm.oid) and publicKey is present only for a v2 key. The version must be v1 (0) or v2 (1), and a [1] public key is permitted only in a v2 key (both directions enforced). A malformed key throws a typed Pkcs8Error (pkcs8/*); a leaf-level codec fault surfaces as asn1/*. pki.schema.pkcs8.pemDecode / pemEncode handle the PEM envelope.
- pki.schema.pkcs8.parseEncrypted — recognizes an EncryptedPrivateKeyInfo ('ENCRYPTED PRIVATE KEY') and surfaces its encryptionAlgorithm and raw encryptedData. Decryption (PBES2/PBKDF2 + a passphrase) is a separate concern and is not performed here. This is an explicit call because an EncryptedPrivateKeyInfo shares its SEQUENCE{SEQUENCE, OCTET STRING} shape with a PKCS#1 DigestInfo, so pki.schema.parse does not auto-route it (structure alone cannot classify it without a validated encryption-algorithm discriminator).
- pki.asn1.read.enumerated's sibling pki.asn1.read.bitStringImplicit and the pki.schema.engine.implicitBitString(tag) leaf — read a context-tagged IMPLICIT BIT STRING (the shape a PKCS#8 OneAsymmetricKey public key [1] takes).

## v0.1.8 — 2026-07-04

A PKCS#10 certification-request parser joins the pki.schema family.

### Added

- pki.schema.csr.parse — a PKCS#10 CertificationRequest parser per RFC 2986. It turns a DER Buffer or a 'CERTIFICATE REQUEST' PEM string into a structured object: version, subject distinguished name, subjectPublicKeyInfo, the requested attributes (each with its type OID, resolved name, and raw-DER values), and the signatureAlgorithm / signatureValue over the CertificationRequestInfo, with the raw certificationRequestInfoBytes returned for signature verification. It composes the shared schema engine and PKIX sub-schemas (AlgorithmIdentifier, Name, SubjectPublicKeyInfo), so a certification request inherits the identical fail-closed structural rules and a malformed request throws a typed CsrError (csr/*); a leaf-level codec fault surfaces as asn1/*. The version must be v1 (INTEGER 0), the [0] IMPLICIT attributes element is mandatory, and each attribute's values SET must be non-empty. pki.schema.parse now detects and routes certification requests, and pki.schema.all() lists it alongside crl and x509. pki.schema.csr.pemDecode / pemEncode handle the PEM envelope.
- pki.asn1.read.enumerated — reads an ENUMERATED value from a decoded node (the same content rules as an INTEGER), the counterpart to the now-strict pki.asn1.read.integer.

### Changed

- C.TIME.ms is renamed to C.TIME.milliseconds, so every C.TIME duration helper now reads as a full word (milliseconds, seconds, minutes, hours, days, weeks). The behavior is unchanged: it still returns an integer millisecond count.

### Security

- pki.asn1.read.integer now rejects an ENUMERATED-tagged node. INTEGER and ENUMERATED share DER content encoding, so an INTEGER-pinned field (a certificate or certification-request version, a serial number, or a cRLNumber) mis-encoded as ENUMERATED was previously decoded as though it were the INTEGER, a type confusion that let malformed DER parse where a conformant reader rejects it. read.integer is now strict on the tag, and ENUMERATED values are read with the new pki.asn1.read.enumerated. Certificate, CRL, and certification-request parsing reject these inputs fail-closed.
- SubjectPublicKeyInfo is now required to be a universal SEQUENCE across the certificate and certification-request parsers. A context-tagged or SET-tagged constructed node carrying a well-formed algorithm and key is no longer accepted as an SPKI.
- SET OF components are now required to be in ascending DER order (X.690 §11.6) wherever the schema declares a SET OF: a relative distinguished name, and a certification request's attributes and attribute values. A non-canonical, unsorted encoding is rejected fail-closed.

### Migration

- Replace C.TIME.ms(n) with C.TIME.milliseconds(n). The other C.TIME and C.BYTES helpers are unchanged.

## v0.1.7 — 2026-07-04

A unified pki.schema family: the structure-schema engine, the X.509 parser, a new CRL parser, and a detect-and-route orchestrator.

### Added

- pki.schema.crl.parse — an X.509 CRL (CertificateList) parser per RFC 5280 §5. It turns a DER Buffer or an 'X509 CRL' PEM string into a structured object: version, issuer distinguished name, thisUpdate / nextUpdate as real Dates, the ordered list of revoked certificates (serial number + hex + revocation date + entry extensions), and the CRL extensions, with the cRLNumber, reasonCode, and invalidityDate values decoded and the raw tbsCertList bytes returned for signature verification. It composes the same schema engine and shared PKIX sub-schemas (AlgorithmIdentifier, Name, Extension) as the certificate parser, so the CertificateList inherits the identical fail-closed structural rules (bounds-checked positional reads, the signature-algorithm agreement, non-empty issuer, extension uniqueness, the v2-only version rule).
- pki.schema.parse — a detect-and-route entry point: hand it DER or PEM and it identifies which registered PKI format the bytes encode (certificate vs CRL) and routes to that member's parser. pki.schema.all() enumerates the registered formats.

### Changed

- The schema engine and the per-format parsers are reorganized under one pki.schema namespace. pki.x509.parse is now pki.schema.x509.parse (and .pemDecode / .pemEncode likewise), and the structure-schema engine pki.asn1.schema is now pki.schema.engine. pki.asn1 remains the strict DER codec (decode / encode / build / read / TAGS). This is a breaking rename with no compatibility shim; see MIGRATING. The schema engine also gained a universal-tag optional-field recognizer, which the CRL's bare version / nextUpdate / revokedCertificates fields require.

### Migration

- Replace pki.x509.parse(...) with pki.schema.x509.parse(...); pki.x509.pemDecode / pemEncode become pki.schema.x509.pemDecode / pemEncode.
- Replace pki.asn1.schema (the structure-schema engine) with pki.schema.engine. pki.asn1 is unchanged for the DER codec (pki.asn1.decode / encode / build / read / TAGS).

## v0.1.6 — 2026-07-04

A declarative ASN.1 structure-schema engine; the X.509 parser is rebuilt on it.

### Added

- pki.asn1.schema — a declarative ASN.1 structure-schema engine. A schema is plain data built from combinators (seq / field / optional / explicit / trailing / seqOf / setOf / setOfUnique / choice, plus the value leaves oidLeaf / integerLeaf / boolean / octetString / bitString / any / decode / time); pki.asn1.schema.walk(schema, node, ctx) interprets it against a decoded DER node under an error namespace, enforcing the structural rules in one place: shape assertion, bounds-checked positional reads, optional / context-tagged fields in strictly increasing tag order, SET-OF uniqueness, and fail-closed typed errors. This is the shared base the certificate parser is built on and the forthcoming CRL / CMS parsers compose, so declaring a new format is a data exercise and no format needs a hand-written decoder.

### Changed

- pki.x509.parse is now built on the schema engine: the Certificate, tbsCertificate, and every sub-structure (AlgorithmIdentifier, Name, Validity, SubjectPublicKeyInfo, Extensions) are declared as schemas and walked. Every valid certificate parses to the same result as before, and every malformed certificate is still rejected. The full existing test suite passes unchanged. The certificate's structural rules (positional bounds, the trailing-field grammar, extension uniqueness, the signature-algorithm agreement) now live in one auditable place instead of a hand-written decoder, and the format is structurally incapable of the positional-read and duplicate-field bug classes. The parser now validates the full certificate structure before applying cross-field checks, so a certificate carrying more than one defect at once may be rejected with a different (still fail-closed) error than a prior release reported.

## v0.1.5 — 2026-07-04

Container healthcheck honors WIKI_PORT; release-tooling supply-chain hardening.

### Fixed

- The example wiki container's HEALTHCHECK now probes the port from WIKI_PORT (defaulting to 3009) where it previously hardcoded 3009, so overriding WIKI_PORT at runtime no longer leaves the container reporting unhealthy while the server is serving on the configured port.

### Security

- The CI secret-scan gate now fetches the gitleaks binary over authenticated requests and verifies it against the checksums file published in the same release before executing it, so a corrupted or tampered download fails closed instead of running as the gate. Tracking the latest release keeps detection rules current.
- The release-container workflow validates that the base image resolved to a well-formed sha256 digest before building against it, so a failed resolution can no longer silently produce an unpinned base. The scanned image is always the published one.
- The workflow-security audit re-runs when its own configuration file changes, so an edit that would suppress a finding is itself audited.

## v0.1.4 — 2026-07-04

The ASN.1 codec's universal-type metadata moves to a single descriptor registry.

### Changed

- The ASN.1/DER codec's universal-type metadata is now defined once in a descriptor registry (each entry carries the type's tag and its required DER encoding form). pki.asn1.TAGS, the primitive-only set (a type DER requires primitive, encoded constructed, is rejected) and the constructed-only set (a SEQUENCE/SET encoded primitive is rejected) are all derived from it, so registering a universal type is a single data entry. This is an internal refactor: the public surface and every decode/encode result are unchanged, and it lays the groundwork for schema-driven format parsers.

## v0.1.3 — 2026-07-04

WebCrypto EC key import validates the curve against the key material.

### Security

- pki.webcrypto.subtle.importKey now derives an imported EC key's named curve from the key material and enforces it across the spki, pkcs8 and jwk formats. Previously it trusted the caller-supplied namedCurve without checking it against the key, so a key on an unsupported curve (for example secp256k1) imported as an approved curve, and a key on one curve could be labeled as another, an algorithm-confusion vector in which the CryptoKey's algorithm disagreed with its key material. A curve the framework does not support is now rejected (NotSupportedError) and a namedCurve that does not match the key is rejected (DataError); generateKey already enforced this, and import now matches it. The raw-key format was already validated against its declared curve and is unchanged.

## v0.1.2 — 2026-07-04

Fail-closed hardening across the DER codec, WebCrypto engine, and X.509 parser.

### Changed

- pki.oid gains registerFamily(base, members): register a whole OID arc family in one call by its shared base arc and each member's trailing leaf. The built-in registry is now declared this way, so a new object identifier is a data entry under its family instead of a re-spelled full path.
- Every primitive now declares the normative reference it is derived from (@spec) and, where it guards a known attack, the class it defends (@defends). The generated reference documentation links each citation to its source (RFC section anchors, NIST FIPS, ITU-T, W3C, CVE and CWE), so the surface is traceable to the standards it implements.

### Fixed

- pki.asn1.read.time rejects semantically invalid UTCTime/GeneralizedTime values (Feb 30, month 13, hour 25, second 60, day 00) instead of silently normalizing them, and preserves a four-digit GeneralizedTime year below 100 instead of remapping it a century, so a malformed or edge-case certificate validity window no longer parses to a shifted instant that disagrees with a strict verifier.
- The DER encoder is now symmetric with the decoder, so no builder can emit DER the decoder would reject: build.utcTime rejects a year outside RFC 5280's 1950-2049 window with no silent century wrap, build.generalizedTime zero-pads the year to four digits, build.set orders its components as DER requires, build.integer/enumerated reject an empty or non-minimal content buffer, build.oid caps each sub-identifier, and build.ia5 rejects non-ASCII bytes.
- String decoding validates each restricted type: IA5String and VisibleString reject bytes outside their permitted range, PrintableString rejects characters outside its restricted set, and UTF8String rejects malformed UTF-8 instead of substituting the Unicode replacement character, closing a parser-differential on certificate name fields.
- BIT STRING decoding enforces DER's requirement that unused trailing bits be zero and rejects an empty BIT STRING that declares unused bits; UniversalString and BMPString decoding reject out-of-range and lone-surrogate code points with a typed Asn1Error instead of a bare RangeError.
- HMAC verify resolves false for a wrong-length signature instead of throwing, per the Web Cryptography API. AES-CTR encrypt/decrypt no longer ignore the counter length parameter: a value other than 128 is rejected.
- pki.x509.parse raises a typed CertificateError (not a generic TypeError) for a truncated tbsCertificate, rejects a certificate carrying duplicate extensions (RFC 5280 §4.2), rejects a tbsCertificate with a repeated or out-of-order trailing field, whether that is a second extensions [3] wrapper (which would otherwise hide the first extension block and split duplicate extension OIDs across two wrappers past the per-extension check) or an out-of-order or unknown context field (RFC 5280 §4.1), rejects an empty issuer distinguished name (RFC 5280 §4.1.2.4) while still permitting an empty subject for the subjectAltName case, rejects an empty or non-SEQUENCE extensions field (RFC 5280 §4.1.2.9) with a typed error, validates the certificate version against the RFC 5280 set, and fails closed on a malformed string in a distinguished name (an invalid-UTF8 or out-of-range name value) instead of hex-escaping the invalid bytes away, so the decoder's strict string validation is enforced on the name path; a genuinely non-string attribute value (a primitive ANY-typed value, or a constructed non-string type such as a SEQUENCE) still renders as its RFC 4514 hex-encoded DER so the name stays representable.
- pki.oid.fromArcs rejects a negative or unsafe-integer arc instead of emitting a malformed OID string; the OID sub-identifier ceiling admits a 128-bit UUID-based arc; and the INTEGER ceiling admits a key at the magnitude cap with its DER sign octet.
- pki.version, pki.C.version, and the CLI now report the installed package version. The value is single-sourced from the package manifest and can no longer drift from the published release.

### Security

- The DER decoder now builds every INTEGER and OID sub-identifier in a single linear pass and refuses any that exceed a per-value byte ceiling (C.LIMITS.DER_MAX_INTEGER_BYTES / OID sub-identifier limit), before reading them. Previously these values were accumulated a byte at a time, which is quadratic in their length: a certificate carrying an oversized serial number or OID arc, well within the overall size cap, could pin a CPU for minutes. This closes a remotely-triggerable decode denial-of-service reachable through pki.x509.parse and pki.asn1.read.*.
- A primitive-encoded SEQUENCE or SET no longer decodes to a leaf node. X.690 §8.9.1/§8.11.1 require these to be constructed, so the DER decoder rejects one. Previously such input decoded to a leaf that pki.x509.parse dereferenced as a structured node, crashing with an uncaught TypeError on attacker-controlled bytes; it now fails closed with a typed error.
- The DER decoder also rejects the mirror violation: a constructed encoding of a universal primitive-only type (INTEGER, OBJECT IDENTIFIER, BOOLEAN, the restricted strings, UTCTime/GeneralizedTime, BIT/OCTET STRING), which is valid BER but not valid DER (X.690 §10.2). Previously a constructed string tag decoded to a childless node that a certificate distinguished name would hex-render, letting an invalid BER/DER name value parse despite the restricted-string content checks; it now fails closed at decode.
- pki.webcrypto.subtle.unwrapKey now enforces the 'unwrapKey' key usage on every unwrap path, including the RSA-OAEP and AES-GCM delegate paths that previously skipped it. An unwrapping key without the 'unwrapKey' usage is now rejected. deriveKey now enforces the distinct 'deriveKey' usage; inheriting 'deriveBits' is no longer enough. Both close cases where an operator-set key-usage restriction could be bypassed.
- pki.x509.parse now rejects a certificate whose outer signatureAlgorithm does not match the signature algorithm inside the signed tbsCertificate (RFC 5280 §4.1.1.2). Surfacing the two AlgorithmIdentifiers without enforcing their equality let a certificate claim one algorithm in the signed body and another in the outer wrapper, a signature-algorithm-substitution vector; the two fields must now be identical.

## v0.1.1 — 2026-07-04

First published release of the 0.1.x foundation.

### Changed

- First release published to npm. The toolkit surface is the 0.1.x foundation: pki.asn1 (strict DER codec), pki.oid (OID ↔ name registry), pki.x509.parse (DER/PEM certificate parsing), and pki.webcrypto (a W3C SubtleCrypto engine over node:crypto with ML-DSA/SLH-DSA signatures alongside the full classical set). It is now available on npm with a SLSA provenance attestation, and served as the pkijs.com documentation container.

## v0.1.0 — 2026-07-04

Initial foundation — a PQC-first WebCrypto engine, a strict DER codec, an OID registry, and X.509 certificate parsing.

### Added

- pki.webcrypto — a zero-dependency W3C Web Cryptography API (Crypto / SubtleCrypto / CryptoKey) built on Node's native node:crypto. PQC-first without being PQC-only: ML-DSA-44/65/87 and SLH-DSA signatures sit alongside the full classical set of RSASSA-PKCS1-v1_5, RSA-PSS, RSA-OAEP, ECDSA, ECDH, Ed25519/Ed448, AES-GCM/CBC/CTR/KW, HMAC, HKDF, PBKDF2, and the SHA family (including legacy SHA-1), plus ML-KEM key generation. Every key and signature it emits is OpenSSL/NSS-interoperable.
- pki.asn1 — a strict, fail-closed DER decoder and canonical encoder with a navigable node tree, typed readers (integer, boolean, OID, bit string, octet string, time, string), and value builders. Rejects indefinite length, non-minimal encodings, and trailing bytes, and enforces size and depth caps (X.690).
- pki.oid — a two-way OID ↔ name registry with dotted/arc conversion, seeded with RFC 5280 attribute types and extensions, the classical signature/public-key/digest algorithms, and the NIST post-quantum arcs (ML-DSA, ML-KEM, SLH-DSA).
- pki.x509.parse — parse DER or PEM X.509 certificates into structured, validated fields: version, serial, signature algorithm, issuer/subject distinguished names, validity window as Date values, subject public-key info, and the extension list, with the exact tbsCertificate bytes exposed for downstream verification.
- pki.C — functional scale constants (C.TIME.*, C.BYTES.*) and shared codec limits.
- pki.errors — a PkiError taxonomy with a defineClass factory and stable domain/reason codes.
- pki command-line front-end (version, oid, parse).

### Security

- The DER decoder is fail-closed: non-DER shapes are rejected and size/depth caps are enforced before the parser walks the input, so a hostile length prefix cannot become a decoder denial-of-service.
- The crypto engine is fail-closed: an unknown algorithm, curve, or format is rejected. There is no silent downgrade, and every sign/verify path returns a real verdict or throws.
