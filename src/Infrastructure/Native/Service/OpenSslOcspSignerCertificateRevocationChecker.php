<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignerCertificateRevocationCheckerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspRequest;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspResponse;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspSingleResponse;

/**
 * Asks every OCSP responder listed in the signing certificate (AIA) for its status before a
 * long-term (LT/LTA) signature is produced.
 *
 * A response is only taken into account when it is verified: its signature must come from the
 * issuer of the signing certificate or from a delegated responder issued by it (carrying
 * id-kp-OCSPSigning, within its validity), the issuer must chain to a self-signed root from the
 * signer's own certificate chain, it must answer the nonce when the responder supports nonces,
 * and it must be current (thisUpdate/nextUpdate with 5 minutes of clock skew; without
 * nextUpdate, at most one day old). A verified "revoked" from any responder is fatal.
 * Unverifiable, stale or missing answers keep the previous behaviour, so offline and
 * OCSP-less certificates are not blocked.
 *
 * Why the signer's own chain is the trust anchor: this is a fail-safe for the signer's
 * certificate, not a validation of someone else's signature. The threat it defends against
 * is a tampered OCSP exchange, and a forged response cannot be signed under the root that
 * issued the signer's certificate. Whoever controls the chain can only make the check
 * inconclusive (the pre-existing behaviour) or block their own signature. Trust decisions
 * about the signature itself stay with the validators, which use their own trust store.
 *
 * The request, the response parsing and the verification are native PHP (ext-openssl);
 * no OpenSSL CLI is involved.
 */
final readonly class OpenSslOcspSignerCertificateRevocationChecker implements SignerCertificateRevocationCheckerInterface
{
    private const CLOCK_SKEW_SECONDS = 300;

    private const MAX_STATUS_AGE_SECONDS = 86400;

    private const OCSP_NETWORK_TIMEOUT_SECONDS = 10;

    private const MAX_CHAIN_DEPTH = 10;

    /**
     * @param  ProcessRunnerInterface  $processRunner  @deprecated unused since OCSP is handled natively; kept for constructor compatibility
     */
    public function __construct(
        private X509ExtensionUrlExtractor $urlExtractor = new X509ExtensionUrlExtractor,
        private ProcessRunnerInterface $processRunner = new ShellProcessRunner,
        private HttpClientInterface $httpClient = new CurlHttpClient,
    ) {}

    public function assertNotRevoked(string $certificatePem, array $chainPem): void
    {
        $certificate = $certificatePem === '' ? false : @openssl_x509_parse($certificatePem);
        if (! is_array($certificate)) {
            return;
        }

        $urls = $this->urlExtractor->ocspUrls($certificate);
        $issuerPem = $this->findIssuer($certificatePem, $certificate, $chainPem);
        $trustAnchors = $this->selfSignedRoots($chainPem);
        if ($urls === [] || $issuerPem === null || $trustAnchors === []
            || ! $this->chainsToTrustAnchor($issuerPem, $chainPem, $trustAnchors)) {
            return;
        }

        foreach ($urls as $url) {
            $revocation = $this->verifiedRevocation($url, $certificatePem, $issuerPem, $chainPem);
            if ($revocation !== null) {
                throw new SignProcessException(sprintf(
                    'The signing certificate "%s" is revoked according to the OCSP responder %s%s.',
                    $this->subject($certificate),
                    $url,
                    $revocation,
                ));
            }
        }
    }

    /**
     * @param  list<string>  $chainPem
     * @return ?string revocation details when the responder returned a verified, current "revoked"
     */
    private function verifiedRevocation(string $url, string $certificatePem, string $issuerPem, array $chainPem): ?string
    {
        $request = OcspRequest::forCertificate($this->pemToDer($certificatePem), $this->pemToDer($issuerPem), random_bytes(16));
        $body = $request?->send($this->httpClient, $url, self::OCSP_NETWORK_TIMEOUT_SECONDS);
        $response = $body === null ? null : OcspResponse::parse($body);
        if ($request === null || $response === null
            || ($response->nonce !== null && ! hash_equals((string) $request->nonce, $response->nonce))
            || ! $this->signedByAuthorizedResponder($response, $issuerPem, $chainPem)) {
            return null;
        }

        $status = $request->findStatus($response);
        if ($status === null || $status->status !== OcspSingleResponse::REVOKED
            || ! $status->isCurrent(time(), self::CLOCK_SKEW_SECONDS, self::MAX_STATUS_AGE_SECONDS)) {
            return null;
        }

        $revokedAt = $status->revocationTime === null ? '' : ' at '.gmdate('M j H:i:s Y \\G\\M\\T', $status->revocationTime);
        $reason = $status->revocationReasonName();

        return $revokedAt.($reason === null ? '' : ' ('.$reason.')');
    }

    /**
     * The response must be signed by the certificate issuer itself or by a responder the issuer
     * delegated with id-kp-OCSPSigning (RFC 6960 section 4.2.2.2).
     *
     * @param  list<string>  $chainPem
     */
    private function signedByAuthorizedResponder(OcspResponse $response, string $issuerPem, array $chainPem): bool
    {
        if ($response->signatureDigest === null) {
            return false;
        }

        $candidates = [$issuerPem, ...array_map($this->derToPem(...), $response->certificates), ...$chainPem];
        foreach ($candidates as $candidatePem) {
            $publicKey = @openssl_pkey_get_public($candidatePem);
            if ($publicKey === false
                || openssl_verify($response->tbsResponseData, $response->signature, $publicKey, $response->signatureDigest) !== 1) {
                continue;
            }

            if ($this->pemToDer($candidatePem) === $this->pemToDer($issuerPem)
                || $this->isDelegatedResponder($candidatePem, $issuerPem)) {
                return true;
            }
        }

        return false;
    }

    private function isDelegatedResponder(string $responderPem, string $issuerPem): bool
    {
        $responder = @openssl_x509_parse($responderPem);
        $issuer = @openssl_x509_parse($issuerPem);
        $extendedKeyUsage = is_array($responder) ? ($responder['extensions']['extendedKeyUsage'] ?? '') : '';

        return is_array($responder) && is_array($issuer)
            && ($responder['issuer'] ?? null) === ($issuer['subject'] ?? false)
            && is_string($extendedKeyUsage)
            && in_array('OCSP Signing', array_map(trim(...), explode(',', $extendedKeyUsage)), true)
            && $this->isWithinValidity($responder)
            && openssl_x509_verify($responderPem, $issuerPem) === 1;
    }

    /**
     * Walks issuer links inside the signer's chain, checking signatures, CA status and validity,
     * until one of the self-signed roots of that chain is reached.
     *
     * @param  list<string>  $chainPem
     * @param  list<string>  $trustAnchors
     */
    private function chainsToTrustAnchor(string $certificatePem, array $chainPem, array $trustAnchors): bool
    {
        $anchors = array_map($this->pemToDer(...), $trustAnchors);
        $current = $certificatePem;
        for ($depth = 0; $depth < self::MAX_CHAIN_DEPTH; $depth++) {
            $parsed = @openssl_x509_parse($current);
            if (! is_array($parsed) || ! $this->isWithinValidity($parsed) || ! $this->isCa($parsed)) {
                return false;
            }

            if (in_array($this->pemToDer($current), $anchors, true)) {
                return true;
            }

            $parent = $this->findIssuer($current, $parsed, $chainPem);
            if ($parent === null) {
                return false;
            }
            $current = $parent;
        }

        return false;
    }

    /**
     * @param  array<string, mixed>  $certificate
     */
    private function isWithinValidity(array $certificate): bool
    {
        $now = time();

        return (int) ($certificate['validFrom_time_t'] ?? PHP_INT_MAX) <= $now
            && (int) ($certificate['validTo_time_t'] ?? 0) >= $now;
    }

    /**
     * basicConstraints CA:TRUE, or a v1 self-signed root without extensions.
     *
     * @param  array<string, mixed>  $certificate
     */
    private function isCa(array $certificate): bool
    {
        $extensions = is_array($certificate['extensions'] ?? null) ? $certificate['extensions'] : [];
        $basicConstraints = $extensions['basicConstraints'] ?? null;

        return is_string($basicConstraints)
            ? str_contains($basicConstraints, 'CA:TRUE')
            : ($certificate['subject'] ?? null) === ($certificate['issuer'] ?? false);
    }

    /**
     * @param  array<string, mixed>  $certificate
     * @param  list<string>  $chainPem
     */
    private function findIssuer(string $certificatePem, array $certificate, array $chainPem): ?string
    {
        foreach ($chainPem as $candidatePem) {
            $candidate = @openssl_x509_parse($candidatePem);
            if (is_array($candidate) && ($candidate['subject'] ?? null) === ($certificate['issuer'] ?? false)
                && openssl_x509_verify($certificatePem, $candidatePem) === 1) {
                return $candidatePem;
            }
        }

        return null;
    }

    /**
     * @param  list<string>  $chainPem
     * @return list<string>
     */
    private function selfSignedRoots(array $chainPem): array
    {
        $roots = [];
        foreach ($chainPem as $candidatePem) {
            $candidate = @openssl_x509_parse($candidatePem);
            if (is_array($candidate) && ($candidate['subject'] ?? null) === ($candidate['issuer'] ?? false)
                && openssl_x509_verify($candidatePem, $candidatePem) === 1) {
                $roots[] = $candidatePem;
            }
        }

        return $roots;
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

    private function pemToDer(string $pem): string
    {
        return base64_decode(preg_replace('/-----[^-]+-----|\\s+/', '', $pem) ?? '');
    }

    private function derToPem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END CERTIFICATE-----\n";
    }
}
