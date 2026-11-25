# Changelog

## 2.0.0 — Unreleased

The library no longer runs any external program. CMS verification, RFC 3161 timestamp
requests and tokens, OCSP, X.509 chain validation and PDF encryption are implemented in PHP on
top of `ext-openssl`; the `openssl` command-line tool and `qpdf` are no longer required at runtime.

### Breaking changes

- Removed the shell abstractions, which no service used anymore:
  - `Infrastructure\Native\Contract\ProcessRunnerInterface`
  - `Infrastructure\Native\Contract\CommandExecutorInterface`
  - `Infrastructure\Native\Service\ShellProcessRunner`
  - `Infrastructure\Native\Service\ShellCommandExecutor`
  - `Infrastructure\Native\ValueObject\ProcessResult`
- Removed `Infrastructure\Native\Service\QpdfPdfProtectionApplier`; use `NativePdfProtectionApplier`.
- Removed the `$processRunner` constructor parameter from the native services. Callers passing it
  by name must drop it; callers passing arguments positionally must shift the ones that followed it:
  - `NativeOcspSignerCertificateRevocationChecker($urlExtractor, $httpClient)`
  - `NativeBrazilPolicyListVerifier($httpClient, $cmsVerifier)`
  - `NativeSignatureTrustVerifier($certificateCollector, $trustAnchorBundleProvider, $pathValidator)`
  - `NativeSignatureCryptoVerifier`, `NativeTimestampTokenVerifier` and
    `NativeRfc3161TimestampTokenValidator` now take `$cmsVerifier` as their first argument
  - `NativeCmsCertificateCollector` and `NativeCmsSignerInfoInspector` take no arguments
- Renamed the services under `Infrastructure\Native\Service` whose `OpenSsl` prefix referred to the
  removed command-line tool, without aliases:

  | 1.x | 2.0 |
  | --- | --- |
  | `OpenSslBrazilPolicyListVerifier` | `NativeBrazilPolicyListVerifier` |
  | `OpenSslCmsCertificateCollector` | `NativeCmsCertificateCollector` |
  | `Inspect\OpenSslCmsSignerInfoInspector` | `Inspect\NativeCmsSignerInfoInspector` |
  | `OpenSslOcspSignerCertificateRevocationChecker` | `NativeOcspSignerCertificateRevocationChecker` |
  | `OpenSslRevocationEvidenceCollector` | `NativeRevocationEvidenceCollector` |
  | `OpenSslRfc3161TimestampTokenProvider` | `NativeRfc3161TimestampTokenProvider` |
  | `OpenSslRfc3161TimestampTokenValidator` | `NativeRfc3161TimestampTokenValidator` |
  | `OpenSslSignatureCryptoVerifier` | `NativeSignatureCryptoVerifier` |
  | `OpenSslSignatureTrustVerifier` | `NativeSignatureTrustVerifier` |
  | `OpenSslTimestampTokenVerifier` | `NativeTimestampTokenVerifier` |

  `Infrastructure\Legacy\OpenSslCertificateValidator` keeps its name: it wraps `ext-openssl`.
- `bin/signer-doctor` no longer checks for the `openssl` binary or `openssl ts`; it reports the
  PHP version, the required PHP extensions and the temporary directory.

### Tests

The test suite still uses the `openssl` command-line tool to issue throwaway certificates,
timestamps and OCSP responses, and `qpdf` as an independent oracle for encrypted PDFs.
