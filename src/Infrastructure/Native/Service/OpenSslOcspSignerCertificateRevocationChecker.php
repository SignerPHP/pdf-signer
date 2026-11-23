<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignerCertificateRevocationCheckerInterface;

/**
 * Asks the OCSP responders listed in the signing certificate (AIA) for its status before a
 * long-term (LT/LTA) signature is produced. Only a definitive "revoked" answer is fatal:
 * without an issuer, responder URL or answer the signature proceeds as before.
 */
final readonly class OpenSslOcspSignerCertificateRevocationChecker implements SignerCertificateRevocationCheckerInterface
{
    public function __construct(
        private X509ExtensionUrlExtractor $urlExtractor = new X509ExtensionUrlExtractor,
        private ProcessRunnerInterface $processRunner = new ShellProcessRunner,
    ) {}

    public function assertNotRevoked(string $certificatePem, array $chainPem): void
    {
        $certificate = $certificatePem === '' ? false : @openssl_x509_parse($certificatePem);
        if (! is_array($certificate)) {
            return;
        }

        $urls = $this->urlExtractor->ocspUrls($certificate);
        $issuerPem = $this->findIssuer($certificate, $chainPem);
        if ($urls === [] || $issuerPem === null) {
            return;
        }

        $certificateFile = $this->tempFile('ocsp-signer-cert', $certificatePem);
        $issuerFile = $this->tempFile('ocsp-signer-issuer', $issuerPem);

        try {
            foreach ($urls as $url) {
                $result = $this->processRunner->run(sprintf(
                    'openssl ocsp -issuer %s -cert %s -url %s -noverify -no_nonce',
                    escapeshellarg($issuerFile),
                    escapeshellarg($certificateFile),
                    escapeshellarg($url),
                ));
                if (! $result->succeeded()) {
                    continue;
                }

                $output = $result->outputAsString();
                if (preg_match('/:\s*revoked\b/i', $output) === 1) {
                    $revokedAt = preg_match('/Revocation Time:\s*(.+)/i', $output, $m) === 1 ? ' at '.trim($m[1]) : '';
                    $reason = preg_match('/Reason:\s*(.+)/i', $output, $m) === 1 ? ' ('.trim($m[1]).')' : '';

                    throw new SignProcessException(sprintf(
                        'The signing certificate "%s" is revoked according to the OCSP responder %s%s%s.',
                        $this->subject($certificate),
                        $url,
                        $revokedAt,
                        $reason,
                    ));
                }

                if (preg_match('/:\s*good\b/i', $output) === 1) {
                    return;
                }
            }
        } finally {
            @unlink($certificateFile);
            @unlink($issuerFile);
        }
    }

    /**
     * @param  array<string, mixed>  $certificate
     * @param  list<string>  $chainPem
     */
    private function findIssuer(array $certificate, array $chainPem): ?string
    {
        foreach ($chainPem as $candidatePem) {
            $candidate = @openssl_x509_parse($candidatePem);
            if (is_array($candidate) && ($candidate['subject'] ?? null) === ($certificate['issuer'] ?? false)) {
                return $candidatePem;
            }
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $certificate
     */
    private function subject(array $certificate): string
    {
        $subject = $certificate['subject'] ?? [];

        return is_array($subject) && isset($subject['CN']) && is_string($subject['CN'])
            ? $subject['CN']
            : (string) ($certificate['name'] ?? 'unknown');
    }

    private function tempFile(string $prefix, string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), $prefix);
        if ($path === false) {
            throw new SignProcessException('Could not create a temporary file for the OCSP check.');
        }
        file_put_contents($path, $contents);

        return $path;
    }
}
