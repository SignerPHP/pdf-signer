<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Infrastructure\Native\Service\Cms;

use SignerPHP\PdfSigner\Domain\Exception\SignProcessException;

final readonly class X509Certificate
{
    public function __construct(
        public string $der,
        public string $issuerNameDer,
        public string $serialIntegerDer,
        public string $pem,
    ) {}

    public static function fromPem(string $pem): self
    {
        $der = self::pemToDer($pem);
        [$tag, $certificate, $end] = Der::readTlv($der, 0);
        if ($tag !== 0x30 || $end !== strlen($der)) {
            throw new SignProcessException('Signing certificate is not a DER SEQUENCE.');
        }

        [$tbsTag, $tbs] = Der::readTlv($certificate, 0);
        if ($tbsTag !== 0x30) {
            throw new SignProcessException('Signing certificate TBS is invalid.');
        }

        $offset = 0;
        [$firstTag] = Der::readTlv($tbs, $offset);
        if ($firstTag === 0xA0) {
            [, , $offset] = Der::readTlv($tbs, $offset);
        }

        [$serialTag, $serialValue, $offset] = Der::readTlv($tbs, $offset);
        if ($serialTag !== 0x02) {
            throw new SignProcessException('Signing certificate serial number is invalid.');
        }

        [, , $offset] = Der::readTlv($tbs, $offset); // signature algorithm
        [$issuerTag, $issuerValue] = Der::readTlv($tbs, $offset);
        if ($issuerTag !== 0x30) {
            throw new SignProcessException('Signing certificate issuer is invalid.');
        }

        return new self(
            der: $der,
            issuerNameDer: Der::tlv(0x30, $issuerValue),
            serialIntegerDer: Der::tlv(0x02, $serialValue),
            pem: $pem,
        );
    }

    public function keyType(): string
    {
        $parsed = openssl_pkey_get_details(openssl_pkey_get_public($this->pem) ?: throw new SignProcessException('Could not read signing certificate public key.'));
        $type = $parsed['type'] ?? null;

        return match ($type) {
            OPENSSL_KEYTYPE_RSA => 'rsa',
            OPENSSL_KEYTYPE_EC => 'ec',
            default => throw new SignProcessException('Unsupported signing certificate key type.'),
        };
    }

    private static function pemToDer(string $pem): string
    {
        if (! str_contains($pem, 'BEGIN')) {
            return $pem;
        }

        $body = preg_replace('/-----[^-]+-----/', '', $pem) ?? '';
        $decoded = base64_decode(preg_replace('/\s+/', '', $body) ?? '', true);
        if ($decoded === false || $decoded === '') {
            throw new SignProcessException('Could not decode signing certificate PEM.');
        }

        return $decoded;
    }
}
