<?php

declare(strict_types=1);

namespace SignerPHP\PdfSigner\Application\DTO;

final readonly class SigningPayload
{
    public function __construct(
        public string $data,
        public HashAlgorithm $algorithm = HashAlgorithm::Sha256,
    ) {}
}
