<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Remote\IntegraIcp;

use SignerPHP\PdfSigner\Application\DTO\ExternalSigningPayload;
use SignerPHP\PdfSigner\Application\DTO\HashAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureAlgorithm;
use SignerPHP\PdfSigner\Application\DTO\SignatureEncoding;
use SignerPHP\PdfSigner\Application\DTO\SignatureValue;
use SignerPHP\PdfSigner\Application\DTO\SigningInputType;
use SignerPHP\PdfSigner\Domain\Exception\SignerException;
use SignerPHP\PdfSigner\RemoteSigning\Contract\RemoteSignatureProviderInterface;
use SignerPHP\PdfSigner\RemoteSigning\DTO\RemoteCertificate;

final readonly class IntegraIcpSignatureProvider implements RemoteSignatureProviderInterface
{
    public function __construct(private IntegraIcpClient $client, private string $credentialId, #[\SensitiveParameter] private string $codeVerifier)
    {
        if (trim($credentialId) === '') {
            throw new \InvalidArgumentException('IntegraICP credential ID cannot be empty.');
        }
        IntegraIcpPkce::challenge($codeVerifier);
    }

    public function sign(ExternalSigningPayload $payload, RemoteCertificate $certificate): SignatureValue
    {
        if ($payload->inputType !== SigningInputType::Digest || $payload->digestAlgorithm !== HashAlgorithm::Sha256
            || $payload->signatureAlgorithm !== SignatureAlgorithm::RsaPkcs1V15 || $payload->signatureEncoding !== SignatureEncoding::RsaPkcs1) {
            throw new SignerException('IntegraICP RAW signing requires SHA-256 with RSA PKCS#1 v1.5.');
        }
        if ($certificate->identifier !== $this->credentialId || strlen($payload->input()) !== 32) {
            throw new SignerException('IntegraICP requires the authorized credential and a SHA-256 digest.');
        }
        $id = bin2hex(random_bytes(12));
        $data = $this->client->json('POST', 'signatures', [
            'credentialId' => $this->credentialId,
            'secretType' => 'code_verifier',
            'secretData' => $this->codeVerifier,
            'requests' => [[
                'contentId' => $id,
                'contentDigest' => $payload->inputBase64,
                'contentDescription' => 'PDF external signature',
                'signaturePolicy' => 'RAW',
            ]],
        ]);
        if (($data['executionStatus']['currentStatus'] ?? null) !== 'COMPLETED_WITH_SUCCESS') {
            throw new SignerException('IntegraICP signature is not completed successfully.');
        }
        $pem = $data['certificateInformation']['encodedX509'] ?? null;
        $expected = openssl_x509_fingerprint($certificate->certificate->certificatePem, 'sha256');
        $actual = is_string($pem) && str_contains($pem, '-----BEGIN CERTIFICATE-----') ? @openssl_x509_fingerprint($pem, 'sha256') : false;
        if ($expected === false || $actual === false || ! hash_equals($expected, $actual)) {
            throw new SignerException('IntegraICP signed with an unexpected certificate.');
        }

        return $this->signature($data, $id, $payload->inputBase64);
    }

    /** @param array<string, mixed> $data */
    private function signature(array $data, string $id, string $digest): SignatureValue
    {
        $items = $data['signatures'] ?? null;
        if (! is_array($items) || ! array_is_list($items) || count($items) !== 1) {
            throw new SignerException('IntegraICP returned an invalid signature list.');
        }
        $item = $items[0];
        $returnedDigest = is_array($item) ? ($item['contentDigest'] ?? null) : null;
        $decodedDigest = is_string($returnedDigest) ? base64_decode($returnedDigest, true) : false;
        if (! is_array($item) || ($item['contentId'] ?? null) !== $id || $decodedDigest !== base64_decode($digest, true)) {
            throw new SignerException('IntegraICP returned an unexpected signature content.');
        }
        $encoded = $item['signedContent'] ?? null;
        $bytes = is_string($encoded) ? base64_decode($encoded, true) : false;
        if ($bytes === false || $bytes === '') {
            throw new SignerException('IntegraICP returned an invalid RAW signature.');
        }

        return new SignatureValue($bytes);
    }
}
