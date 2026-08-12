# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-11

### Added

- XAdES-BES enveloped signature generation compatible with the SRI (Ecuador)
  electronic invoicing requirements:
  - Signature structure mirrors the XAdES4J implementation accepted by the SRI:
    three `ds:Reference` entries in order `SignedProperties` -> `KeyInfo` ->
    document, `ds:KeyInfo` with `xades:Certificate` plus `ds:KeyValue` /
    `ds:RSAKeyValue` (modulus/exponent), `xades:Description`
    ("contenido comprobante") and `xades:MimeType` in `DataObjectFormat`,
    base64 wrapping at 76 columns, and namespaces normalized on the
    `ds:Signature` root element.
  - SHA-1 as the default digest and signature algorithm (`rsa-sha1`),
    matching the XAdES4J reference; SHA-256 (`rsa-sha256`) remains available
    through `SignatureContext`.
  - `Signer` API (`signFromString`, `signFromFile`) with an immutable
    `SignatureContext` (digest algorithm, signing time, mime type,
    `DataObjectFormat` toggle, signature id).
  - `P12CertificateLoader` to read PKCS#12 (.p12) containers into an
    `OpensslPrivateKeySigner`.
- `PrivateKeySignerInterface` abstraction so the same signing pipeline works
  with remote/HSM signers or any external key service.
- `BatchSigner` to sign every `*.xml` file in a directory or an arbitrary list
  of files in one pass, without aborting on a single failure.
- `Verifier` with multi-layer checks:
  - RSA signature of the canonicalized `SignedInfo` (algorithm derived from
    `ds:SignatureMethod`, not assumed),
  - document digest with the `ds:Signature` element removed,
  - `xades:SignedProperties` digest,
  - `ds:KeyInfo` digest,
  - `xades:CertDigest` / `xades:IssuerSerial` against the embedded certificate,
  - embedded certificate validity window.
  - `VerificationResult` exposes per-check booleans, errors, signer common
    name, signing time and signature id.
- CLI (`bin/xades-bes`): `sign` (single file or directory, `--sha256` option,
  default SHA-1) and `verify` commands.
- Test suite (PHPUnit) covering certificate parsing, signature structure,
  verification round-trips, tampering detection, batch signing and schema
  compliance against the official SRI `factura_V1.1.0.xsd` and
  `xmldsig-core-schema.xsd` schemas.
- Fixtures: a schema-valid sample invoice (`sri-factura-unsigned.xml`) and a
  generator script (`tests/fixtures/generate-test-cert.php`, wired to
  `composer fixtures:generate`) that produces the `test-cert.p12` used by the
  tests.
- `docker/openssl.cnf` enabling the OpenSSL legacy provider (required to read
  legacy-encrypted PKCS#12 containers with OpenSSL 3.x).
- MIT license.

### Fixed

- Certificate date parsing now handles both ASN.1 UTCTime (12 digits,
  e.g. `250101000000Z`) and GeneralizedTime (14 digits, e.g.
  `21260714043916Z`) values instead of failing on certificates valid past 2049.
- Verification derives SHA-1 vs SHA-256 from the actual `ds:SignatureMethod`
  element rather than assuming SHA-256.
- Default digest algorithm aligned to SHA-1 across the public API
  (`SignatureContext` and `P12CertificateLoader`), so signing with a plain
  `new SignatureContext()` and loading the key with the library default
  always produce a mutually consistent signature.
