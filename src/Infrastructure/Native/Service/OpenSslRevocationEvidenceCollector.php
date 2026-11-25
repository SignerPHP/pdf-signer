<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service;

use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\ProcessRunnerInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\SignatureRevocationEvidenceCollectorInterface;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspRequest;
use SignerPHP\PdfSigner\Infrastructure\Native\Service\Ocsp\OcspResponse;

/**
 * Collects CRLs and OCSP responses for every certificate of a signature chain, to be embedded
 * in the DSS (PAdES LT/LTA). OCSP requests are built and sent natively; the responses are
 * stored as received (validators verify them), as long as they are successful basic responses
 * answering for the requested certificate.
 */
final readonly class OpenSslRevocationEvidenceCollector implements SignatureRevocationEvidenceCollectorInterface
{
    private const OCSP_NETWORK_TIMEOUT_SECONDS = 10;

    /**
     * @param  ProcessRunnerInterface  $processRunner  @deprecated unused since OCSP is handled natively; kept for constructor compatibility
     */
    public function __construct(
        private X509ExtensionUrlExtractor $urlExtractor = new X509ExtensionUrlExtractor,
        private HttpClientInterface $httpClient = new CurlHttpClient,
        private ProcessRunnerInterface $processRunner = new ShellProcessRunner,
    ) {}

    public function collect(array $certificateChainDer): array
    {
        $result = [];

        foreach ($certificateChainDer as $index => $certDer) {
            $parsed = $this->parseCertificate($certDer);
            if ($parsed === null) {
                $result[$index] = ['ocsp' => [], 'crl' => []];

                continue;
            }

            $crls = $this->collectCrls($this->urlExtractor->crlUrls($parsed));
            $ocsps = $this->collectOcspResponses(
                $certDer,
                $this->issuerCandidates($certificateChainDer, $index),
                $this->urlExtractor->ocspUrls($parsed)
            );

            $result[$index] = [
                'ocsp' => $ocsps,
                'crl' => $crls,
            ];
        }

        return $result;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function parseCertificate(string $certDer): ?array
    {
        $pem = $this->derToPem($certDer);
        if ($pem === null) {
            return null;
        }

        $parsed = @openssl_x509_parse($pem, false);
        if (! is_array($parsed)) {
            return null;
        }

        return $parsed;
    }

    private function derToPem(string $der): ?string
    {
        if ($der === '') {
            return null;
        }

        return "-----BEGIN CERTIFICATE-----\n".
            chunk_split(base64_encode($der), 64, "\n").
            "-----END CERTIFICATE-----\n";
    }

    /**
     * @param  array<int, string>  $urls
     * @return array<int, string>
     */
    private function collectCrls(array $urls): array
    {
        $responses = [];

        foreach ($urls as $url) {
            $body = $this->fetchBinaryViaCurl($url, 10);
            if ($body === false || $body === '') {
                continue;
            }

            $responses[] = $body;
        }

        return $this->dedupeBinary($responses);
    }

    private function fetchBinaryViaCurl(string $url, int $timeoutSeconds): string|false
    {
        $response = $this->httpClient->request('GET', $url, [], '', $timeoutSeconds, true);
        if (! $response->isSuccessful() || $response->body === '' || $response->transportError !== null) {
            return false;
        }

        return $response->body;
    }

    /**
     * @param  array<int, string>  $issuerCandidatesDer
     * @param  array<int, string>  $urls
     * @return array<int, string>
     */
    private function collectOcspResponses(string $certDer, array $issuerCandidatesDer, array $urls): array
    {
        $certPem = $this->derToPem($certDer);
        if ($certPem === null || $urls === []) {
            return [];
        }

        $responses = [];
        foreach ($issuerCandidatesDer as $issuerDer) {
            $issuerPem = (string) $this->derToPem($issuerDer);
            $request = @openssl_x509_verify($certPem, $issuerPem) === 1
                ? OcspRequest::forCertificate($certDer, $issuerDer)
                : null;
            if ($request === null) {
                continue;
            }

            foreach ($urls as $url) {
                $body = $request->send($this->httpClient, $url, self::OCSP_NETWORK_TIMEOUT_SECONDS);
                $response = $body === null ? null : OcspResponse::parse($body);
                if ($body !== null && $response !== null && $request->findStatus($response) !== null) {
                    $responses[] = $body;
                }
            }
        }

        return $this->dedupeBinary($responses);
    }

    /**
     * @param  array<int, string>  $chain
     * @return array<int, string>
     */
    private function issuerCandidates(array $chain, int $certIndex): array
    {
        $ordered = [];

        for ($i = $certIndex + 1; $i < count($chain); $i++) {
            $ordered[] = $chain[$i];
        }

        for ($i = 0; $i < count($chain); $i++) {
            if ($i === $certIndex || $i > $certIndex) {
                continue;
            }

            $ordered[] = $chain[$i];
        }

        return $this->dedupeBinary($ordered);
    }

    /**
     * @param  array<int, string>  $items
     * @return array<int, string>
     */
    private function dedupeBinary(array $items): array
    {
        $unique = [];
        foreach ($items as $item) {
            if ($item === '') {
                continue;
            }

            $unique[hash('sha256', $item)] = $item;
        }

        return array_values($unique);
    }
}
