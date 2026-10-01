<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\Vidaas;

use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureEncoding;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningInputType;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\Infrastructure\Native\Contract\HttpClientInterface;

final readonly class VidaasProvider
{
    public const PRODUCTION_URL = 'https://certificado.vidaas.com.br';

    public const SANDBOX_URL = 'https://hml-certificado.vidaas.com.br';

    private const CERTIFICATE_PATH = '/v0/oauth/certificate-discovery-authorization';

    private const SIGNATURE_PATH = '/v0/oauth/signature';

    public function __construct(
        private string $accessToken,
        private HttpClientInterface $httpClient,
        private string $baseUrl = self::PRODUCTION_URL,
        private int $timeoutSeconds = 20,
    ) {
        if (trim($this->accessToken) === '') {
            throw new SignerException('VIDaaS access token cannot be empty.');
        }
    }

    /** @return list<VidaasCertificate> */
    public function certificates(?string $certificateAlias = null): array
    {
        $path = self::CERTIFICATE_PATH;
        if ($certificateAlias !== null && trim($certificateAlias) !== '') {
            $path .= '?certificate_alias='.rawurlencode(trim($certificateAlias));
        }

        $json = $this->authorizedJson('GET', $path);
        $items = $json['certificates'] ?? $json;
        if (! is_array($items)) {
            throw new SignerException('VIDaaS certificate discovery response is invalid.');
        }

        $certificates = [];
        foreach ($items as $item) {
            if (! is_array($item)) {
                continue;
            }

            $alias = $item['alias'] ?? $item['certificate_alias'] ?? null;
            $certificate = $item['certificate'] ?? $item['certificatePem'] ?? null;
            if (! is_string($alias) || trim($alias) === '' || ! is_string($certificate) || trim($certificate) === '') {
                continue;
            }

            $certificates[] = new VidaasCertificate(trim($alias), $this->normalizeCertificate($certificate));
        }

        if ($certificates === []) {
            throw new SignerException('VIDaaS did not return any usable certificate.');
        }

        return $certificates;
    }

    public function sign(ExternalSigningPayload $payload, string $certificateAlias): SignatureValue
    {
        if (
            $payload->inputType !== SigningInputType::Digest
            || $payload->digestAlgorithm !== HashAlgorithm::Sha256
            || $payload->signatureAlgorithm !== SignatureAlgorithm::RsaPkcs1V15
            || $payload->signatureEncoding !== SignatureEncoding::RsaPkcs1
        ) {
            throw new SignerException('VIDaaS RAW signing currently requires SHA-256 with RSA PKCS#1 v1.5.');
        }

        if (trim($certificateAlias) === '') {
            throw new SignerException('VIDaaS certificate alias cannot be empty.');
        }

        $digest = $payload->input();
        if (strlen($digest) !== 32) {
            throw new SignerException('VIDaaS signing payload must contain a valid SHA-256 digest.');
        }

        $id = bin2hex(random_bytes(12));
        $json = $this->authorizedJson('POST', self::SIGNATURE_PATH, [
            'certificate_alias' => trim($certificateAlias),
            'hashes' => [[
                'id' => $id,
                'alias' => 'external-signature',
                'hash' => $payload->inputBase64,
                'hash_algorithm' => '2.16.840.1.101.3.4.2.1',
                'signature_format' => 'RAW',
                'padding_method' => 'PKCS1V1_5',
            ]],
        ]);
        $signatures = $json['signatures'] ?? null;
        if (! is_array($signatures)) {
            throw new SignerException('VIDaaS signature response does not contain signatures.');
        }

        $returnedAlias = $json['certificate_alias'] ?? null;
        if (! is_string($returnedAlias) || ! hash_equals(trim($certificateAlias), trim($returnedAlias))) {
            throw new SignerException('VIDaaS signed with an unexpected certificate alias.');
        }

        foreach ($signatures as $signature) {
            if (! is_array($signature) || ($signature['id'] ?? null) !== $id) {
                continue;
            }

            $raw = $signature['raw_signature'] ?? null;
            $bytes = is_string($raw) ? base64_decode(preg_replace('/\s+/', '', $raw) ?? '', true) : false;
            if (is_string($bytes) && $bytes !== '') {
                return new SignatureValue($bytes);
            }
        }

        throw new SignerException('VIDaaS signature response does not contain a valid raw signature.');
    }

    /** @param array<string, mixed> $payload */
    private function authorizedJson(string $method, string $path, array $payload = []): array
    {
        $body = $payload === [] ? '' : json_encode($payload, JSON_THROW_ON_ERROR);
        $headers = ['Authorization: Bearer '.$this->accessToken, 'Accept: application/json'];
        if ($body !== '') {
            $headers[] = 'Content-Type: application/json';
        }

        $response = $this->httpClient->request(
            $method,
            rtrim($this->baseUrl, '/').$path,
            $headers,
            $body,
            $this->timeoutSeconds,
        );

        return self::successfulJson($response->statusCode, $response->body, $path);
    }

    /** @return array<string, mixed> */
    private static function successfulJson(int $statusCode, string $body, string $operation): array
    {
        if ($statusCode < 200 || $statusCode >= 300) {
            throw new SignerException(sprintf('VIDaaS %s failed with HTTP %d.', $operation, $statusCode));
        }

        $json = json_decode($body, true);
        if (! is_array($json)) {
            throw new SignerException(sprintf('VIDaaS %s returned invalid JSON.', $operation));
        }

        return $json;
    }

    private function normalizeCertificate(string $certificate): string
    {
        $certificate = trim($certificate);
        if (str_contains($certificate, '-----BEGIN CERTIFICATE-----')) {
            return $certificate."\n";
        }

        $der = base64_decode(preg_replace('/\s+/', '', $certificate) ?? '', true);
        if (! is_string($der) || $der === '') {
            throw new SignerException('VIDaaS returned an invalid certificate.');
        }

        return "-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END CERTIFICATE-----\n";
    }
}
