<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

final readonly class ExternalSigningPayload
{
    public function __construct(
        public string $dataBase64,
        public string $digestBase64,
        public HashAlgorithm $digestAlgorithm,
        public SignatureAlgorithm $signatureAlgorithm,
        public string $input = 'cms-signed-attributes',
        public string $encoding = 'base64',
        public string $signatureEncoding = 'binary',
    ) {}

    public function data(): string
    {
        $data = base64_decode($this->dataBase64, true);

        if (! is_string($data)) {
            throw new \InvalidArgumentException('External signing payload contains invalid base64 data.');
        }

        return $data;
    }
}
