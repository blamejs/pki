# Sigstore conformance fixtures

Interoperability vectors for `pki.sigstore.verifyBundle`. They were produced by cosign against the
Sigstore public-good instance and are the same bytes every other Sigstore client is tested against.

| File | Source path |
|---|---|
| `a.txt` | `test/assets/bundle-verify/a.txt` |
| `happy-path-v0.1.sigstore.json` | `test/assets/bundle-verify/happy-path-v0.1/bundle.sigstore.json` |
| `happy-path-v0.2.sigstore.json` | `test/assets/bundle-verify/happy-path-v0.2/bundle.sigstore.json` |
| `happy-path-v0.3.sigstore.json` | `test/assets/bundle-verify/happy-path-v0.3/bundle.sigstore.json` |

- **Repository:** https://github.com/sigstore/sigstore-conformance
- **Commit:** `bf6b322ef65839216ec8853287032750e1f4b92d`
- **License:** Apache-2.0
- **Retrieved:** 2026-09-08

`a.txt` is 109 bytes and its SHA-256 is
`a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf`.

All three bundles carry a `message_signature` content arm over that artifact and a `hashedrekord`
v0.0.1 log entry. The v0.1 and v0.2 bundles carry an `x509CertificateChain`; v0.3 carries a single
`certificate`. The v0.1 and v0.2 entries were logged at 1689177396 and the v0.3 entry at 1710869186,
so the two vintages exercise different points in the trust material's validity windows. The Fulcio
certificate authority, the Rekor log key and the certificate-transparency log key that these bundles
need are all in `../trusted-root.json`, which is why no additional trust fixture ships with them.

The signature in each covers the raw bytes of `a.txt`, not a digest of them.
