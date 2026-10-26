# CMS signed attributes and PDF signature profiles

## Supported signing modes

| Mode | CMS signed attributes | PDF `/SubFilter` |
| --- | --- | --- |
| `pdf-basic` | `contentType`, `messageDigest`, `signingTime` | `/adbe.pkcs7.detached` |
| PAdES Baseline B/T/LT/LTA | `contentType`, `messageDigest`, ESS signing-certificate reference; no CMS `signingTime` | `/ETSI.CAdES.detached` |

PAdES modes use `signingCertificateV2` (RFC 5035) for SHA-224, SHA-256, SHA-384
and SHA-512. The compatibility-only SHA-1 algorithm uses `signingCertificate`
(RFC 2634). These attributes contain the hash of the **complete DER-encoded
signer certificate** and its issuer/serial number. ESSCertIDv2 omits the SHA-256
algorithm identifier when using its default, and encodes other hash algorithms
explicitly. This does not imply SHA-1 is suitable for current PAdES signatures.

The PDF signature dictionary still contains its required `/M` signing-time
entry. Both flows preserve `contentType`, `messageDigest` and `ByteRange`.

## Signing and external preparation

CMS construction is shared by synchronous signing and external preparation.
The preparation stage requires only the public certificate, not a private key.
It returns an unchanged base64-encoded digest of the DER signed-attributes SET;
the caller signs that digest using the declared algorithm. Completion expects
raw RSA PKCS#1 v1.5 signature bytes or DER-encoded ECDSA signature bytes, as
indicated in `signatureEncoding`. Prepared attributes and the original format
of the serialized state are preserved across process restarts.

## Independent conformance evidence

Run `composer tests:conformance` using the project's existing Pest/PHPUnit
test runner and the system `openssl` CLI. These tests also run under the
`signing-contracts` suite and the regular coverage gate. Disposable RSA and
ECDSA certificates exercise PDF basic and PAdES B-B, with both synchronous
signing and external signing completed in a separate process after its
private key has been removed. OpenSSL independently verifies CMS cryptography,
local test-certificate trust, ASN.1 signed attributes and DER certificate hash
binding; PHP assertions check PDF `SubFilter`, `/M`, `ByteRange` and the signed
content digest. No additional programming-language runtime is required.

This is a targeted automated conformance contract, **not** an accredited
profile-conformance certificate. PAdES B-T additionally requires valid trusted
timestamps; B-LT requires suitable certificate and revocation evidence; B-LTA
requires conforming archival timestamps. The higher profiles have additional
policy and trust requirements that are not established by these B-B fixtures.
